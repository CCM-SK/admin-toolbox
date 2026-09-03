const $ = (selector, root = document) => root.querySelector(selector);

function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function cleanIp(value) {
    return String(value ?? '').trim().replace(/^\[|\]$/g, '');
}

function parseIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${ip}`);
    let value = 0;
    for (const part of parts) {
        if (!/^\d+$/.test(part)) throw new Error(`Invalid IPv4 address: ${ip}`);
        const n = Number(part);
        if (n < 0 || n > 255) throw new Error(`Invalid IPv4 address: ${ip}`);
        value = value * 256 + n;
    }
    return BigInt(value);
}

function ipv4ToString(value) {
    const n = Number(value);
    return [
        (n >>> 24) & 255,
        (n >>> 16) & 255,
        (n >>> 8) & 255,
        n & 255
    ].join('.');
}

function expandIPv6(ip) {
    let value = cleanIp(ip).toLowerCase();
    if (value.includes('%')) value = value.split('%')[0];

    if (value.includes('.')) {
        const lastColon = value.lastIndexOf(':');
        const v4 = value.slice(lastColon + 1);
        const v4n = parseIPv4(v4);
        const hi = Number((v4n >> 16n) & 0xffffn).toString(16);
        const lo = Number(v4n & 0xffffn).toString(16);
        value = value.slice(0, lastColon + 1) + hi + ':' + lo;
    }

    const pieces = value.split('::');
    if (pieces.length > 2) throw new Error(`Invalid IPv6 address: ${ip}`);

    const left = pieces[0] ? pieces[0].split(':').filter(Boolean) : [];
    const right = pieces.length === 2 && pieces[1] ? pieces[1].split(':').filter(Boolean) : [];

    if (left.some(x => !/^[0-9a-f]{1,4}$/.test(x)) ||
        right.some(x => !/^[0-9a-f]{1,4}$/.test(x))) {
        throw new Error(`Invalid IPv6 address: ${ip}`);
    }

    if (pieces.length === 1 && left.length !== 8) {
        throw new Error(`Invalid IPv6 address: ${ip}`);
    }

    const missing = 8 - left.length - right.length;
    if (missing < 0 || (pieces.length === 1 && missing !== 0)) {
        throw new Error(`Invalid IPv6 address: ${ip}`);
    }

    const groups = [
        ...left.map(x => parseInt(x, 16)),
        ...Array(missing).fill(0),
        ...right.map(x => parseInt(x, 16))
    ];
    return groups;
}

function parseIPv6(ip) {
    const groups = expandIPv6(ip);
    let value = 0n;
    for (const group of groups) value = (value << 16n) | BigInt(group);
    return value;
}

function ipv6ToString(value) {
    const groups = new Array(8);
    let n = value;
    for (let i = 7; i >= 0; i--) {
        groups[i] = Number(n & 0xffffn);
        n >>= 16n;
    }

    let bestStart = -1, bestLen = 0;
    let start = -1;
    for (let i = 0; i <= 8; i++) {
        if (i < 8 && groups[i] === 0) {
            if (start === -1) start = i;
        } else if (start !== -1) {
            const len = i - start;
            if (len > bestLen && len >= 2) {
                bestStart = start;
                bestLen = len;
            }
            start = -1;
        }
    }

    const out = [];
    for (let i = 0; i < 8; i++) {
        if (i === bestStart) {
            out.push('');
            i += bestLen - 1;
            if (i === 7) out.push('');
        } else {
            out.push(groups[i].toString(16));
        }
    }
    return out.join(':');
}

function detectFamily(ip) {
    const raw = cleanIp(ip);
    if (raw.includes(':')) return 6;
    if (raw.includes('.')) return 4;
    throw new Error(`Unable to determine IP version: ${ip}`);
}

function parseCIDR(line) {
    const text = String(line ?? '').trim();
    if (!text) return null;

    const slash = text.lastIndexOf('/');
    if (slash <= 0 || slash === text.length - 1) {
        throw new Error(`Invalid CIDR: ${text}`);
    }

    const ipText = cleanIp(text.slice(0, slash));
    const prefixText = text.slice(slash + 1).trim();
    if (!/^\d+$/.test(prefixText)) throw new Error(`Invalid prefix length: ${text}`);

    const version = detectFamily(ipText);
    const bits = version === 4 ? 32 : 128;
    const prefix = Number(prefixText);
    if (prefix < 0 || prefix > bits) throw new Error(`Prefix /${prefix} is invalid for IPv${version}`);

    const input = version === 4 ? parseIPv4(ipText) : parseIPv6(ipText);
    const allOnes = (1n << BigInt(bits)) - 1n;
    const hostBits = bits - prefix;
    const mask = prefix === 0 ? 0n : (allOnes ^ ((1n << BigInt(hostBits)) - 1n));
    const start = input & mask;
    const end = start + ((1n << BigInt(hostBits)) - 1n);

    return {
        original: text,
        version,
        bits,
        prefix,
        start,
        end,
        count: 1n << BigInt(hostBits)
    };
}

function cidrString(start, prefix, version) {
    return `${version === 4 ? ipv4ToString(start) : ipv6ToString(start)}/${prefix}`;
}

function addressString(value, version) {
    return version === 4 ? ipv4ToString(value) : ipv6ToString(value);
}

function compareRanges(a, b) {
    if (a.start < b.start) return -1;
    if (a.start > b.start) return 1;
    if (a.end < b.end) return -1;
    if (a.end > b.end) return 1;
    return a.original.localeCompare(b.original);
}

function overlaps(a, b) {
    return a.start <= b.end && b.start <= a.end;
}

function strictlyContains(a, b) {
    return a.start <= b.start && a.end >= b.end && !(a.start === b.start && a.end === b.end);
}

function commonBounds(ranges) {
    const start = ranges.reduce((m, r) => r.start < m ? r.start : m, ranges[0].start);
    const end = ranges.reduce((m, r) => r.end > m ? r.end : m, ranges[0].end);
    return { start, end };
}

function smallestSupernet(ranges) {
    const version = ranges[0].version;
    const bits = ranges[0].bits;
    const bounds = commonBounds(ranges);
    let prefix = 0;

    for (let p = 0; p <= bits; p++) {
        const hostBits = bits - p;
        const mask = p === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(hostBits)) - 1n);
        const start = bounds.start & mask;
        const end = start + ((1n << BigInt(hostBits)) - 1n);
        if (start <= bounds.start && end >= bounds.end) {
            prefix = p;
            break;
        }
    }

    const hostBits = bits - prefix;
    const mask = prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(hostBits)) - 1n);
    const start = bounds.start & mask;
    return {
        version,
        prefix,
        start,
        end: start + ((1n << BigInt(hostBits)) - 1n),
        count: 1n << BigInt(hostBits)
    };
}

function maskForPrefix(prefix, bits) {
    if (prefix === 0) return 0n;
    return ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - prefix)) - 1n);
}

function cidrCover(start, end, version) {
    const bits = version === 4 ? 32 : 128;
    const maxBlock = 1n << BigInt(bits);

    if (start < 0n || end < start || end >= maxBlock) return [];

    const result = [];
    let cursor = start;

    while (cursor <= end) {
        let maxSize;
        if (cursor === 0n) {
            maxSize = maxBlock;
        } else {
            const lowbit = cursor & (-cursor);
            maxSize = lowbit;
        }

        const remaining = end - cursor + 1n;
        while (maxSize > remaining) maxSize >>= 1n;

        let hostBits = 0;
        let tmp = maxSize;
        while (tmp > 1n) {
            tmp >>= 1n;
            hostBits++;
        }
        const prefix = bits - hostBits;
        result.push(cidrString(cursor, prefix, version));
        cursor += maxSize;
    }
    return result;
}

function mergeRanges(ranges) {
    const sorted = [...ranges].sort(compareRanges);
    const merged = [];

    for (const range of sorted) {
        const last = merged[merged.length - 1];
        if (!last || range.start > last.end + 1n) {
            merged.push({ version: range.version, start: range.start, end: range.end });
        } else if (range.end > last.end) {
            last.end = range.end;
        }
    }

    return merged;
}

function rangeLabel(start, end, version) {
    return `${addressString(start, version)} – ${addressString(end, version)}`;
}

function hostUsableCount(range) {
    if (range.version === 4) {
        if (range.prefix === 31) return 2n; // point-to-point RFC 3021
        if (range.prefix === 32) return 1n;
        if (range.count <= 2n) return 0n;
        return range.count - 2n;
    }
    return range.count;
}

function formatCount(value) {
    return BigInt(value).toLocaleString();
}

function formatDualCounts(count) {
    if (count <= 9007199254740991n) return Number(count).toLocaleString();
    return count.toLocaleString();
}

function sectionCard(title, body) {
    return `<div class="card"><h3>${title}</h3>${body}</div>`;
}

function statusBadge(kind, label) {
    return `<span class="badge ${kind}">${label}</span>`;
}

export function renderRangeAnalyzer(app) {
    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>IP Range / CIDR Overlap Analyzer</h2>
            <p class="small">Paste IPv4 and/or IPv6 CIDRs — one per line. Everything is calculated locally.</p>
          </div>
          <span class="badge ok"></span>
        </div>

        <div class="card">
          <label for="range-input">CIDR ranges</label>
          <textarea id="range-input" rows="10" spellcheck="false"
            placeholder="10.10.0.0/16&#10;10.10.20.0/24&#10;10.10.20.128/25&#10;10.11.0.0/16"></textarea>
          <div class="row between">
            <span class="muted" id="range-line-count">0 entries</span>
            <div class="row">
              <button class="btn secondary" id="range-example" type="button">Load example</button>
              <button class="btn secondary" id="range-clear" type="button">Clear</button>
              <button class="btn primary" id="range-analyze" type="button">Analyze</button>
            </div>
          </div>
        </div>

        <div id="range-message" class="notice hidden" role="status"></div>

        <div id="range-results">
          <div class="grid three">
            <div class="stat"><span>Ranges</span><strong id="range-count">0</strong></div>
            <div class="stat"><span>IPv4</span><strong id="range-v4">0</strong></div>
            <div class="stat"><span>IPv6</span><strong id="range-v6">0</strong></div>
          </div>

          <div class="grid two range-section">
            <div class="card">
              <div class="row between">
                <h3>Smallest supernet</h3>
                <span id="range-supernet-status"></span>
              </div>
              <div class="mono" id="range-supernet">—</div>
              <div class="muted" id="range-supernet-details">—</div>
            </div>
            <div class="card">
              <h3>Total address space</h3>
              <div class="grid two">
                <div class="stat"><span>Input CIDRs</span><strong id="range-total-input">0</strong></div>
                <div class="stat"><span>Unique covered</span><strong id="range-total-unique">0</strong></div>
              </div>
              <div class="muted" id="range-total-note"></div>
            </div>
          </div>

          <div class="grid two range-section">
            <div class="card">
              <h3>Usable host totals</h3>
              <div class="grid two">
                <div class="stat"><span>Input CIDRs</span><strong id="range-usable-input">0</strong></div>
                <div class="stat"><span>Unique covered</span><strong id="range-usable-unique">0</strong></div>
              </div>
              <div class="muted">IPv4: /31 is counted as 2 usable point-to-point addresses and /32 as 1. IPv6 reports all assigned addresses as usable.</div>
            </div>
            <div class="card">
              <h3>Gaps</h3>
              <div id="range-gaps">—</div>
              <div class="muted range-subnote">Gaps are measured only inside the smallest common supernet.</div>
            </div>
          </div>

          <div class="range-section">
            <div class="card">
              <h3>Overlaps & containment</h3>
              <div id="range-relations">—</div>
            </div>

            <div class="card">
              <h3>Duplicate ranges</h3>
              <div id="range-duplicates">—</div>
            </div>

            <div class="card">
              <h3>Mergeable CIDRs</h3>
              <div id="range-mergeable">—</div>
              <div class="muted range-subnote">The tool shows a minimal CIDR cover after overlapping and adjacent input ranges are merged.</div>
            </div>

            <div class="card">
              <div class="row between">
                <h3>Parsed ranges</h3>
                <button class="btn secondary" id="range-export" type="button">Copy JSON</button>
              </div>
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr><th>#</th><th>Input</th><th>Normalized</th><th>Range</th><th>Addresses</th><th>Usable</th></tr>
                  </thead>
                  <tbody id="range-table"></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </section>
    `;

    const input = $('#range-input');
    const message = $('#range-message');
    let lastExport = null;

    const example = [
        '10.10.0.0/16',
        '10.10.20.0/24',
        '10.10.20.128/25',
        '10.11.0.0/16'
    ].join('\n');

    function showMessage(text, kind = 'error') {
        message.textContent = text || '';
        message.className = text ? `notice ${kind}` : 'notice hidden';
    }

    function updateLineCount() {
        const lines = input.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
        $('#range-line-count').textContent = `${lines.length.toLocaleString()} entr${lines.length === 1 ? 'y' : 'ies'}`;
    }

    function resetOutput() {
        ['range-count', 'range-v4', 'range-v6', 'range-total-input', 'range-total-unique',
         'range-usable-input', 'range-usable-unique'].forEach(id => { $(`#${id}`).textContent = '0'; });
        $('#range-supernet').textContent = '—';
        $('#range-supernet-details').textContent = '—';
        $('#range-supernet-status').textContent = '';
        $('#range-total-note').textContent = '';
        $('#range-gaps').textContent = '—';
        $('#range-relations').textContent = '—';
        $('#range-duplicates').textContent = '—';
        $('#range-mergeable').textContent = '—';
        $('#range-table').innerHTML = '';
        lastExport = null;
    }

    function analyze() {
        const lines = input.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
        if (!lines.length) {
            resetOutput();
            showMessage('Enter at least one CIDR range.', 'error');
            return;
        }

        try {
            const ranges = lines.map(parseCIDR);
            const families = new Set(ranges.map(r => r.version));
            if (families.size > 1) {
                throw new Error('IPv4 and IPv6 ranges cannot be compared to each other. Analyze one address family at a time.');
            }

            ranges.forEach((r, i) => { r.index = i + 1; });
            const version = ranges[0].version;

            $('#range-count').textContent = ranges.length.toLocaleString();
            $('#range-v4').textContent = version === 4 ? ranges.length.toLocaleString() : '0';
            $('#range-v6').textContent = version === 6 ? ranges.length.toLocaleString() : '0';

            const totalInput = ranges.reduce((n, r) => n + r.count, 0n);
            const merged = mergeRanges(ranges);
            const uniqueTotal = merged.reduce((n, r) => n + (r.end - r.start + 1n), 0n);
            const usableInput = ranges.reduce((n, r) => n + hostUsableCount(r), 0n);
            const usableUnique = merged.reduce((n, r) => {
                const fake = { version, prefix: 0, count: r.end - r.start + 1n };
                if (version === 4) {
                    const count = fake.count;
                    if (count === 1n) return n + 1n;
                    if (count === 2n) return n + 2n;
                    return n + count - 2n;
                }
                return n + fake.count;
            }, 0n);

            $('#range-total-input').textContent = formatDualCounts(totalInput);
            $('#range-total-unique').textContent = formatDualCounts(uniqueTotal);
            $('#range-usable-input').textContent = formatDualCounts(usableInput);
            $('#range-usable-unique').textContent = formatDualCounts(usableUnique);

            const supernet = smallestSupernet(ranges);
            $('#range-supernet').textContent = cidrString(supernet.start, supernet.prefix, version);
            $('#range-supernet-details').textContent =
                `${rangeLabel(supernet.start, supernet.end, version)} · ${formatDualCounts(supernet.count)} addresses`;
            $('#range-supernet-status').innerHTML = statusBadge('ok', 'BOUND');

            const duplicateMap = new Map();
            for (const r of ranges) {
                const key = `${r.start}/${r.prefix}`;
                if (!duplicateMap.has(key)) duplicateMap.set(key, []);
                duplicateMap.get(key).push(r);
            }
            const duplicateGroups = [...duplicateMap.values()].filter(g => g.length > 1);
            $('#range-duplicates').innerHTML = duplicateGroups.length
                ? duplicateGroups.map(g => `<div class="mono">${esc(cidrString(g[0].start, g[0].prefix, version))} — ${g.length} copies</div>`).join('')
                : '<span class="muted">No duplicate CIDRs.</span>';

            const relations = [];
            for (let i = 0; i < ranges.length; i++) {
                for (let j = i + 1; j < ranges.length; j++) {
                    const a = ranges[i], b = ranges[j];
                    if (!overlaps(a, b)) continue;

                    const equal = a.start === b.start && a.end === b.end;
                    if (equal) {
                        relations.push({
                            kind: 'duplicate',
                            text: `${a.original} = ${b.original}`
                        });
                    } else if (strictlyContains(a, b)) {
                        relations.push({
                            kind: 'contains',
                            text: `${a.original} contains ${b.original}`
                        });
                    } else if (strictlyContains(b, a)) {
                        relations.push({
                            kind: 'contains',
                            text: `${b.original} contains ${a.original}`
                        });
                    } else {
                        relations.push({
                            kind: 'overlap',
                            text: `${a.original} overlaps ${b.original}`
                        });
                    }
                }
            }

            $('#range-relations').innerHTML = relations.length
                ? `<div class="stack">${relations.map(r => {
                    const cls = r.kind === 'duplicate' ? 'warn' : r.kind === 'contains' ? 'ok' : 'warn';
                    const icon = r.kind === 'duplicate' ? 'DUPLICATE' : r.kind === 'contains' ? 'CONTAINED' : 'OVERLAP';
                    return `<div class="row between"><span>${esc(r.text)}</span>${statusBadge(cls, icon)}</div>`;
                }).join('')}</div>`
                : '<span class="muted">No overlaps or containment relationships.</span>';

            // Gaps within the smallest supernet after merging covered intervals.
            const gaps = [];
            let cursor = supernet.start;
            for (const m of merged) {
                if (m.start > cursor) gaps.push({ start: cursor, end: m.start - 1n });
                if (m.end + 1n > cursor) cursor = m.end + 1n;
            }
            if (cursor <= supernet.end) gaps.push({ start: cursor, end: supernet.end });

            $('#range-gaps').innerHTML = gaps.length
                ? `<div class="stack">${gaps.map(g => {
                    const count = g.end - g.start + 1n;
                    return `<div class="row between"><span class="mono">${esc(rangeLabel(g.start, g.end, version))}</span><span>${formatDualCounts(count)} addresses</span></div>`;
                }).join('')}</div>`
                : `<span class="ok">No gaps inside ${esc(cidrString(supernet.start, supernet.prefix, version))}.</span>`;

            const mergedCidrList = merged.flatMap(m => cidrCover(m.start, m.end, version));
            const originalsNormalized = new Set(ranges.map(r => cidrString(r.start, r.prefix, version)));
            const usefulMerged = mergedCidrList.filter(c => !originalsNormalized.has(c));

            $('#range-mergeable').innerHTML = usefulMerged.length
                ? `<div class="mono">${usefulMerged.map(esc).join('<br>')}</div>`
                : '<span class="muted">No additional mergeable CIDRs; input is already minimal after overlap/adjacency consolidation.</span>';

            $('#range-table').innerHTML = ranges
                .sort(compareRanges)
                .map((r, idx) => `
                    <tr>
                      <td>${idx + 1}</td>
                      <td class="mono">${esc(r.original)}</td>
                      <td class="mono">${esc(cidrString(r.start, r.prefix, version))}</td>
                      <td class="mono">${esc(rangeLabel(r.start, r.end, version))}</td>
                      <td>${formatDualCounts(r.count)}</td>
                      <td>${formatDualCounts(hostUsableCount(r))}</td>
                    </tr>
                `).join('');

            lastExport = {
                tool: 'Admin Toolbox — IP Range / CIDR Overlap Analyzer',
                version,
                input: lines,
                smallestSupernet: cidrString(supernet.start, supernet.prefix, version),
                totalInputAddresses: totalInput.toString(),
                uniqueCoveredAddresses: uniqueTotal.toString(),
                usableInputAddresses: usableInput.toString(),
                usableUniqueAddresses: usableUnique.toString(),
                overlapsAndContainment: relations,
                duplicateRanges: duplicateGroups.map(g => ({
                    cidr: cidrString(g[0].start, g[0].prefix, version),
                    copies: g.length
                })),
                gaps: gaps.map(g => ({
                    start: addressString(g.start, version),
                    end: addressString(g.end, version),
                    addresses: (g.end - g.start + 1n).toString()
                })),
                mergedCidrs: mergedCidrList,
                note: 'Gaps are calculated only within the smallest common supernet. IPv4 usable counts follow /31 point-to-point and /32 single-host conventions; IPv6 usable equals total addresses.'
            };

            showMessage(
                `Analysis complete: ${ranges.length} range${ranges.length === 1 ? '' : 's'}, ` +
                `${relations.length} relationship${relations.length === 1 ? '' : 's'}, ` +
                `${gaps.length} gap${gaps.length === 1 ? '' : 's'}.`,
                'success'
            );
        } catch (err) {
            resetOutput();
            showMessage(err?.message || 'Unable to analyze the ranges.', 'error');
        }
    }

    input.addEventListener('input', updateLineCount);
    $('#range-example').addEventListener('click', () => {
        input.value = example;
        updateLineCount();
        analyze();
    });
    $('#range-clear').addEventListener('click', () => {
        input.value = '';
        updateLineCount();
        resetOutput();
        showMessage('');
    });
    $('#range-analyze').addEventListener('click', analyze);
    $('#range-export').addEventListener('click', async () => {
        if (!lastExport) {
            showMessage('Analyze the ranges first.', 'error');
            return;
        }
        const text = JSON.stringify(lastExport, null, 2);
        try {
            await navigator.clipboard.writeText(text);
            showMessage('JSON analysis copied to clipboard.', 'success');
        } catch {
            showMessage('Clipboard access was blocked. Select and copy the JSON from developer tools instead.', 'error');
        }
    });

    updateLineCount();
    input.value = example;
    updateLineCount();
    analyze();
}