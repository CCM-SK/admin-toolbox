const WINDOWS_EPOCH_MS = Date.UTC(1601, 0, 1);
const UNIX_EPOCH_MS = Date.UTC(1970, 0, 1);
const TICKS_PER_MS = 10_000n;
const TICKS_PER_SECOND = 10_000_000n;

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

function inRange(ms) {
    return (
        Number.isFinite(ms) &&
        ms >= Date.UTC(1970, 0, 1) &&
        ms < Date.UTC(2500, 0, 1)
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
    if (!inRange(ms)) {
        throw new Error(
            'Unix seconds value is outside the supported range.'
        );
    }

    return ms;
}

function unixMs(value) {
    const ms = Number(int64(value));
    if (!inRange(ms)) {
        throw new Error(
            'Unix/JavaScript milliseconds value is outside the supported range.'
        );
    }

    return ms;
}

function filetime(value) {
    const ticks = int64(value);
    const wholeMs = ticks / TICKS_PER_MS;
    const remainder = ticks % TICKS_PER_MS;

    const ms =
        Number(wholeMs) +
        WINDOWS_EPOCH_MS +
        Number(remainder) / 10_000;

    if (!inRange(ms)) {
        throw new Error(
            'FILETIME value is outside the supported range.'
        );
    }

    return ms;
}

function parseDate(value) {
    const ms = Date.parse(String(value).trim());

    if (Number.isNaN(ms) || !inRange(ms)) {
        throw new Error('Invalid or unsupported date/time value.');
    }

    return ms;
}

function eventLogDate(value) {
    const text = String(value).trim();

    const systemTimeMatch = text.match(
        /SystemTime\s*=\s*["']([^"']+)["']/i
    );

    const cleaned = (
        systemTimeMatch ? systemTimeMatch[1] : text
    ).replace(
        /^\s*(?:TimeCreated|DateTime|Timestamp)\s*[:=]\s*/i,
        ''
    );

    const normalized = cleaned.replace(
        /(\.\d{3})\d+(?=Z|[+-]\d{2}:?\d{2}|$)/,
        '$1'
    );

    return parseDate(normalized);
}

function hexBig(value) {
    const cleaned = String(value)
        .trim()
        .replace(/^0x/i, '')
        .replace(/[\s:_-]/g, '');

    if (!cleaned || !/^[0-9a-f]+$/i.test(cleaned)) {
        throw new Error('Invalid hexadecimal timestamp.');
    }

    return BigInt(`0x${cleaned}`);
}

function hexCandidates(value) {
    const cleaned = String(value)
        .trim()
        .replace(/^0x/i, '')
        .replace(/[\s:_-]/g, '');

    if (!cleaned || !/^[0-9a-f]+$/i.test(cleaned)) {
        return [];
    }

    const number = Number(BigInt(`0x${cleaned}`));
    const candidates = [];
    const unixSecondsMs = number * 1000;

    if (inRange(unixSecondsMs)) {
        candidates.push({
            format: 'Hex → Unix seconds',
            ms: unixSecondsMs,
            confidence: cleaned.length <= 10 ? 85 : 70
        });
    }

    const unixMilliseconds = number;
    if (inRange(unixMilliseconds)) {
        candidates.push({
            format: 'Hex → Unix milliseconds',
            ms: unixMilliseconds,
            confidence: cleaned.length >= 10 ? 65 : 45
        });
    }

    const filetimeMs =
        number / 10_000 + WINDOWS_EPOCH_MS;

    if (inRange(filetimeMs)) {
        candidates.push({
            format: 'Hex → Windows FILETIME',
            ms: filetimeMs,
            confidence: cleaned.length >= 14 ? 95 : 75
        });
    }

    return candidates.sort(
        (a, b) => b.confidence - a.confidence
    );
}

function heuristic(value) {
    const text = String(value).trim();
    const candidates = [];

    if (/^\d+$/.test(text)) {
        if (text.length <= 10) {
            try {
                candidates.push({
                    format: 'Unix seconds',
                    ms: unixSec(text),
                    confidence: 95
                });
            } catch { }
        }

        if (text.length >= 11 && text.length <= 14) {
            try {
                candidates.push({
                    format: 'Unix milliseconds / JavaScript milliseconds',
                    ms: unixMs(text),
                    confidence: 95
                });
            } catch { }
        }

        if (text.length >= 15 && text.length <= 18) {
            try {
                candidates.push({
                    format: 'Windows FILETIME',
                    ms: filetime(text),
                    confidence: 92
                });
            } catch { }
        }
    }

    const looksLikeHex =
        /^0x[0-9a-f]+$/i.test(text) ||
        /^[0-9a-f]{8,16}$/i.test(
            text.replace(/[\s:_-]/g, '')
        );

    if (looksLikeHex) {
        candidates.push(...hexCandidates(text));
    }

    const looksLikeEventLog =
        /SystemTime\s*=/i.test(text) ||
        /^\s*(?:TimeCreated|DateTime|Timestamp)\s*[:=]/i.test(text);

    if (looksLikeEventLog) {
        try {
            candidates.push({
                format: 'Windows Event Log-style timestamp',
                ms: eventLogDate(text),
                confidence: 99
            });
        } catch { }
    }

    const looksLikeIsoDate =
        /^\d{4}-\d{2}-\d{2}[T ]/.test(text) ||
        /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),/i.test(text) ||
        /(Z|[+-]\d{2}:?\d{2})$/i.test(text);

    if (looksLikeIsoDate) {
        try {
            candidates.push({
                format: 'ISO-8601 / RFC 3339 / date-time',
                ms: parseDate(text),
                confidence: 96
            });
        } catch { }
    }

    if (/^\d{1,2}[/-]\d{1,2}[/-]\d{4}[ T]/.test(text)) {
        try {
            candidates.push({
                format: 'Windows/Event Viewer local date-time',
                ms: eventLogDate(text),
                confidence: 82
            });
        } catch { }
    }

    return candidates.sort(
        (a, b) => b.confidence - a.confidence
    );
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function all(ms) {
    const unixSeconds = Math.floor(
        (ms - UNIX_EPOCH_MS) / 1000
    );

    const unixMilliseconds = Math.round(
        ms - UNIX_EPOCH_MS
    );

    const filetime = BigInt(
        Math.round((ms - WINDOWS_EPOCH_MS) * 10_000)
    );

    const filetimeHex = filetime
        .toString(16)
        .padStart(16, '0')
        .toUpperCase();

    return {
        sec: unixSeconds,
        ums: unixMilliseconds,
        iso: isoUtc(ms),
        local: localIso(ms),
        filetime: filetime.toString(),
        filetimeHex: `0x${filetimeHex}`,
        secHex:
            `0x${Math.max(0, unixSeconds)
                .toString(16)
                .padStart(8, '0')
                .toUpperCase()}`,
        msHex:
            `0x${Math.max(0, unixMilliseconds)
                .toString(16)
                .padStart(8, '0')
                .toUpperCase()}`
    };
}

export function renderTimestamp(app) {
    app.innerHTML = `
        <section class="card">
            <div class="row between">
                <div>
                    <h2>Timestamp / Epoch Converter</h2>
                    <p class="small">
                        Convert common timestamp formats locally, or identify an unknown value heuristically.
                    </p>
                </div>

                <span class="badge ok"></span>
            </div>

            <div class="card">
                <div class="row between">
                    <label for="ts-input">Timestamp</label>

                    <select id="ts-mode">
                        <option value="heuristic">
                            What timestamp format is this?
                        </option>
                        <option value="unix-seconds">
                            Unix seconds
                        </option>
                        <option value="unix-ms">
                            Unix milliseconds
                        </option>
                        <option value="javascript-ms">
                            JavaScript milliseconds
                        </option>
                        <option value="iso">
                            ISO-8601 / RFC 3339
                        </option>
                        <option value="eventlog">
                            Windows Event Log
                        </option>
                        <option value="filetime">
                            Windows FILETIME
                        </option>
                        <option value="hex">
                            Hex timestamp
                        </option>
                    </select>
                </div>

                <input
                    id="ts-input"
                    type="text"
                    value="1724064000"
                    placeholder="e.g. 1724064000, 1724064000000, 0x01DB..., 2025-01-01T12:00:00Z"
                >

                <div class="row">
                    <button
                        class="btn primary"
                        type="button"
                        id="ts-convert"
                    >
                        Convert
                    </button>

                    <button
                        class="btn secondary"
                        type="button"
                        id="ts-now"
                    >
                        Use current time
                    </button>

                    <button
                        class="btn secondary"
                        type="button"
                        id="ts-clear"
                    >
                        Clear
                    </button>
                </div>
            </div>

            <div
                id="ts-message"
                class="notice hidden"
                role="status"
            ></div>

            <div class="card">
                <h3>Quick result</h3>
                <div id="ts-quick"></div>
            </div>

            <div id="ts-heuristics" class="card">
                <h3>Heuristic candidates</h3>
                <div id="ts-candidates"></div>
            </div>

            <div class="card">
                <h3>UTC / local</h3>

                <div class="grid two">
                    <div class="stat">
                        <span>UTC</span>
                        <strong id="ts-utc">—</strong>
                    </div>

                    <div class="stat">
                        <span>Local time</span>
                        <strong id="ts-local">—</strong>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Equivalent representations</h3>

                <div class="grid two">
                    <div class="stat">
                        <span>Unix seconds</span>
                        <strong id="ts-sec">—</strong>
                    </div>

                    <div class="stat">
                        <span>Unix milliseconds</span>
                        <strong id="ts-ms">—</strong>
                    </div>

                    <div class="stat">
                        <span>JavaScript milliseconds</span>
                        <strong id="ts-js">—</strong>
                    </div>

                    <div class="stat">
                        <span>Windows FILETIME</span>
                        <strong id="ts-ft">—</strong>
                    </div>

                    <div class="stat">
                        <span>FILETIME hex</span>
                        <strong id="ts-fth">—</strong>
                    </div>

                    <div class="stat">
                        <span>Unix seconds hex</span>
                        <strong id="ts-sech">—</strong>
                    </div>

                    <div class="stat">
                        <span>Unix milliseconds hex</span>
                        <strong id="ts-msh">—</strong>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3>Reference notes</h3>

                <ul>
                    <li>
                        Unix seconds/milliseconds count from
                        1970-01-01 UTC.
                    </li>
                    <li>
                        JavaScript <span class="mono">Date.now()</span>
                        uses Unix milliseconds.
                    </li>
                    <li>
                        Windows FILETIME uses 100-ns ticks since
                        1601-01-01 UTC.
                    </li>
                    <li>
                        Timezone-less ISO/Event Viewer values are
                        interpreted using the browser's local timezone.
                    </li>
                    <li>
                        Hex mode tests common Unix and FILETIME
                        interpretations; heuristic matches are
                        suggestions, not proof.
                    </li>
                </ul>
            </div>
        </section>
    `;

    const $ = selector => app.querySelector(selector);

    const input = $('#ts-input');
    const mode = $('#ts-mode');
    const message = $('#ts-message');
    const candidates = $('#ts-candidates');
    const heuristics = $('#ts-heuristics');

    function notice(text, kind = 'error') {
        message.textContent = text || '';
        message.className = text
            ? `notice ${kind}`
            : 'notice hidden';
    }

    function render(ms) {
        const result = all(ms);

        $('#ts-utc').textContent = result.iso;
        $('#ts-local').textContent = result.local;

        $('#ts-sec').textContent =
            result.sec.toLocaleString();

        $('#ts-ms').textContent =
            result.ums.toLocaleString();

        $('#ts-js').textContent =
            result.ums.toLocaleString();

        $('#ts-ft').textContent = result.filetime;
        $('#ts-fth').textContent = result.filetimeHex;
        $('#ts-sech').textContent = result.secHex;
        $('#ts-msh').textContent = result.msHex;

        $('#ts-quick').innerHTML = `
            <div class="grid two">
                <div class="stat">
                    <span>Date (UTC)</span>
                    <strong>${escapeHtml(result.iso)}</strong>
                </div>

                <div class="stat">
                    <span>Date (local)</span>
                    <strong>${escapeHtml(result.local)}</strong>
                </div>
            </div>
        `;
    }

    function renderCandidates(list) {
        if (!list.length) {
            candidates.innerHTML =
                '<div class="muted">No confident timestamp interpretation was found.</div>';
            return;
        }

        candidates.innerHTML = list
            .map((candidate, index) => {
                const isBestMatch = index === 0;
                const badgeClass = isBestMatch ? 'ok' : '';
                const badgeText = isBestMatch
                    ? 'BEST MATCH'
                    : 'POSSIBLE';

                return `
                    <div class="card compact">
                        <div class="row between">
                            <div>
                                <strong>
                                    ${escapeHtml(candidate.format)}
                                </strong>

                                <div class="muted">
                                    ${escapeHtml(
                                        isoUtc(candidate.ms)
                                    )}
                                </div>
                            </div>

                            <span class="badge ${badgeClass}">
                                ${badgeText} · ${candidate.confidence}%
                            </span>
                        </div>

                        <div class="muted">
                            Local:
                            ${escapeHtml(localIso(candidate.ms))}
                        </div>
                    </div>
                `;
            })
            .join('');
    }

    function convert() {
        try {
            const text = input.value.trim();

            if (!text) {
                throw new Error('Enter a timestamp.');
            }

            if (mode.value === 'heuristic') {
                const list = heuristic(text);

                heuristics.classList.remove('hidden');
                renderCandidates(list);

                if (!list.length) {
                    $('#ts-quick').innerHTML =
                        '<div class="muted">No likely format found.</div>';

                    notice(
                        'No strong match. Try selecting a specific format.'
                    );

                    return;
                }

                render(list[0].ms);

                notice(
                    `Best match: ${list[0].format} (${list[0].confidence}% confidence).`,
                    'success'
                );

                return;
            }

            heuristics.classList.add('hidden');

            let ms;

            switch (mode.value) {
                case 'unix-seconds':
                    ms = unixSec(text);
                    break;

                case 'unix-ms':
                case 'javascript-ms':
                    ms = unixMs(text);
                    break;

                case 'iso':
                case 'rfc3339':
                    ms = parseDate(text);
                    break;

                case 'eventlog':
                    ms = eventLogDate(text);
                    break;

                case 'filetime':
                    ms = filetime(text);
                    break;

                case 'hex': {
                    const list = hexCandidates(text);

                    if (!list.length) {
                        throw new Error(
                            'Could not interpret the hexadecimal timestamp.'
                        );
                    }

                    ms = list[0].ms;
                    break;
                }

                default:
                    throw new Error('Unsupported mode.');
            }

            render(ms);
            notice('Conversion successful.', 'success');

        } catch (error) {
            candidates.innerHTML =
                '<div class="muted">—</div>';

            $('#ts-quick').innerHTML =
                '<div class="muted">No result.</div>';

            notice(
                error?.message ||
                'Could not parse timestamp.'
            );
        }
    }

    $('#ts-convert').onclick = convert;

    input.onkeydown = event => {
        if (event.key === 'Enter') {
            event.preventDefault();
            convert();
        }
    };

    $('#ts-now').onclick = () => {
        input.value = String(Date.now());
        mode.value = 'javascript-ms';
        convert();
    };

    $('#ts-clear').onclick = () => {
        input.value = '';

        $('#ts-quick').innerHTML =
            '<div class="muted">No result.</div>';

        [
            'ts-utc',
            'ts-local',
            'ts-sec',
            'ts-ms',
            'ts-js',
            'ts-ft',
            'ts-fth',
            'ts-sech',
            'ts-msh'
        ].forEach(id => {
            $('#' + id).textContent = '—';
        });

        candidates.innerHTML =
            '<div class="muted">—</div>';

        notice('');
    };

    mode.onchange = () => {
        heuristics.classList.toggle(
            'hidden',
            mode.value !== 'heuristic'
        );
    };

    convert();
}