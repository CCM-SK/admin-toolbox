function esc(v) {
    return String(v ?? '')
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const PERM = {
    u: { r: 4, w: 2, x: 1 },
    g: { r: 4, w: 2, x: 1 },
    o: { r: 4, w: 2, x: 1 }
};

function digitBits(d) {
    return {
        r: (d & 4) !== 0,
        w: (d & 2) !== 0,
        x: (d & 1) !== 0
    };
}

function bitsDigit(bits) {
    return (bits.r ? 4 : 0) + (bits.w ? 2 : 0) + (bits.x ? 1 : 0);
}

function modeToSymbolic(mode, type = '-') {
    const special = (mode >> 9) & 0x7;
    const u = (mode >> 6) & 7;
    const g = (mode >> 3) & 7;
    const o = mode & 7;

    const part = (digit, specialBit, specialChar) => {
        const b = digitBits(digit);
        let s = (b.r ? 'r' : '-') + (b.w ? 'w' : '-');
        if (b.x) {
            s += specialBit ? specialChar : 'x';
        } else {
            s += specialBit ? specialChar.toUpperCase() : '-';
        }
        return s;
    };

    return type + part(u, special & 4, 's') +
        part(g, special & 2, 's') +
        part(o, special & 1, 't');
}

function modeToOctal(mode) {
    return String(mode.toString(8).padStart(4, '0'));
}

function modeToChmod(mode) {
    return `chmod ${modeToOctal(mode)}`;
}

function parseOctal(input) {
    const clean = String(input).trim().replace(/^0o/i, '');
    if (!/^[0-7]{3,4}$/.test(clean)) {
        throw new Error('Enter a 3- or 4-digit octal mode, such as 755, 0644, or 4755.');
    }
    return parseInt(clean, 8);
}

function parseLsPermission(input) {
    const clean = String(input).trim();
    if (!/^[bcdlps-][rwxXsStT-]{9}$/.test(clean)) {
        throw new Error('Not a valid ls -l permission string. Example: -rwxr-xr-x');
    }

    const type = clean[0];
    const chars = clean.slice(1);

    let mode = 0;
    const set = (pos, bit) => {
        if (chars[pos] !== '-') mode |= bit;
    };

    set(0, 0o400);
    set(1, 0o200);
    if (chars[2] === 'x' || chars[2] === 's') mode |= 0o100;
    if (chars[2] === 's') mode |= 0o4000;

    set(3, 0o040);
    set(4, 0o020);
    if (chars[5] === 'x' || chars[5] === 's') mode |= 0o010;
    if (chars[5] === 's') mode |= 0o2000;

    set(6, 0o004);
    set(7, 0o002);
    if (chars[8] === 'x' || chars[8] === 't') mode |= 0o001;
    if (chars[8] === 't') mode |= 0o1000;

    return { mode, type };
}

function parseSymbolic(input, initialMode = 0, type = '-') {
    let mode = initialMode;
    const expr = String(input).trim();

    if (!expr) {
        throw new Error('Enter a symbolic mode such as u=rwx,g=rx,o=rx.');
    }

    for (const rawClause of expr.split(',')) {
        const clause = rawClause.trim();
        const m = clause.match(/^([ugoas]*)([+=-])([rwxXstugo]*)(?:([0-7]+))?$/);

        if (!m) {
            throw new Error(`Invalid symbolic clause: ${clause}`);
        }

        const whoRaw = m[1].toLowerCase() || 'a';
        const op = m[2];
        const perms = m[3];
        const numeric = m[4];

        let who = new Set();

        if (whoRaw.includes('a') || whoRaw === 'a') {
            who = new Set(['u', 'g', 'o']);
        } else {
            for (const c of whoRaw) {
                who.add(c);
            }
        }

        if (numeric) {
            const d = parseInt(numeric, 8);

            if (numeric.length > 1) {
                throw new Error(
                    'Numeric symbolic mode must use one octal digit per selected class.'
                );
            }

            for (const w of who) {
                const shift = w === 'u' ? 6 : w === 'g' ? 3 : 0;
                const mask = 7 << shift;

                if (op === '=') {
                    mode = (mode & ~mask) | (d << shift);
                } else if (op === '+') {
                    mode |= d << shift;
                } else {
                    mode &= ~(d << shift);
                }
            }

            continue;
        }
        let ordinary = 0;
        let special = 0;
        let hasX = false;
        for (const p of perms) {
            if (p === 'r') ordinary |= 4;
            if (p === 'w') ordinary |= 2;
            if (p === 'x') ordinary |= 1;
            if (p === 'X') {
                hasX = true;
            }
            if (p === 's' && (who.has('u') || who.has('g'))) {
                if (who.has('u')) special |= 0o4000;
                if (who.has('g')) special |= 0o2000;
            }
            if (p === 't' && who.has('o')) {
                special |= 0o1000;
            }
        }

        if (hasX) {
            const anyExec = (mode & 0o111) !== 0;

            if (type === 'd' || anyExec) {
                ordinary |= 1;
            }
        }
        for (const w of who) {
            const shift = w === 'u' ? 6 : w === 'g' ? 3 : 0;
            const mask = 7 << shift;
            if (op === '=') {
                mode &= ~mask;
                mode |= ordinary << shift;
            } else if (op === '+') {
                mode |= ordinary << shift;
            } else if (op === '-') {
                mode &= ~(ordinary << shift);
            }
        }

        if (op === '-') {
            mode &= ~special;
        } else if (op === '+') {
            mode |= special;
        } else {
            mode = (mode & ~0o7000) | special;
        }
    }

    return mode;
}

function permissionMeaning(mode) {
    const u = digitBits((mode >> 6) & 7);
    const g = digitBits((mode >> 3) & 7);
    const o = digitBits(mode & 7);

    const rows = [
        ['Owner', u, 'owner'],
        ['Group', g, 'group'],
        ['Others', o, 'others']
    ];

    return rows.map(([label, bits]) => ({
        label,
        read: bits.r,
        write: bits.w,
        execute: bits.x
    }));
}

function specialBits(mode) {
    return {
        setuid: (mode & 0o4000) !== 0,
        setgid: (mode & 0o2000) !== 0,
        sticky: (mode & 0o1000) !== 0
    };
}

function riskFindings(mode, type = '-') {
    const f = [];
    const s = specialBits(mode);

    if ((mode & 0o002) !== 0) {
        f.push({
            level: 'high',
            title: 'World-writable',
            detail: 'Others have write permission. This can be risky for files and sensitive directories.'
        });
    }

    if ((mode & 0o020) !== 0) {
        f.push({
            level: 'warning',
            title: 'Group-writable',
            detail: 'The group has write permission. Verify that every member of the group should be able to modify the object.'
        });
    }

    if ((mode & 0o004) !== 0 && type !== 'd') {
        f.push({
            level: 'warning',
            title: 'World-readable',
            detail: 'Others have read permission. Verify that the file is intended to be broadly readable.'
        });
    }

    if (s.setuid) {
        f.push({
            level: 'high',
            title: 'Setuid enabled',
            detail: 'The executable may run with the file owner’s effective UID on systems that implement setuid semantics.'
        });
    }

    if (s.setgid) {
        f.push({
            level: 'warning',
            title: 'Setgid enabled',
            detail: 'The object has the setgid special bit.'
        });
    }

    if (s.sticky && type === 'd') {
        f.push({
            level: 'info',
            title: 'Sticky bit enabled',
            detail: 'For a directory, deletion/rename is constrained by the sticky-bit rules of the platform.'
        });
    }

    if (type === 'd' && (mode & 0o001) && !(mode & 0o002)) {
        f.push({
            level: 'info',
            title: 'Others can traverse',
            detail: 'Others have directory execute permission, allowing traversal when the path is otherwise accessible.'
        });
    }

    return f;
}

function symbolicSuggestion(mode) {
    const parts = [];
    const special = specialBits(mode);
    for (const [who, shift] of [['u',6],['g',3],['o',0]]) {
        const d = (mode >> shift) & 7;
        const bits = digitBits(d);
        let p = '';
        if (bits.r) p += 'r';
        if (bits.w) p += 'w';
        if (bits.x) p += 'x';
        parts.push(`${who}=${p || ''}`);
    }
    if (special.setuid) parts.push('u+s');
    if (special.setgid) parts.push('g+s');
    if (special.sticky) parts.push('o+t');
    return parts.join(',');
}

function renderDetails(root, mode, type = '-') {
    const $ = s => root.querySelector(s);

    const octal = modeToOctal(mode);
    const symbolic = modeToSymbolic(mode, type);
    const rows = permissionMeaning(mode);
    const special = specialBits(mode);

    $('#chmod-octal').textContent = octal;
    $('#chmod-symbolic').textContent = symbolic;
    $('#chmod-command').textContent = modeToChmod(mode);

    $('#chmod-owner').textContent = `${(mode >> 6) & 7}`;
    $('#chmod-group').textContent = `${(mode >> 3) & 7}`;
    $('#chmod-others').textContent = `${mode & 7}`;

    $('#chmod-setuid').textContent = special.setuid ? 'Enabled' : 'Disabled';
    $('#chmod-setgid').textContent = special.setgid ? 'Enabled' : 'Disabled';
    $('#chmod-sticky').textContent = special.sticky ? 'Enabled' : 'Disabled';

    $('#chmod-matrix').innerHTML = rows.map(r => `
      <tr>
        <th>${esc(r.label)}</th>
        <td>${r.read ? '✓' : '—'}</td>
        <td>${r.write ? '✓' : '—'}</td>
        <td>${r.execute ? '✓' : '—'}</td>
      </tr>
    `).join('');

    const findings = riskFindings(mode, type);
    $('#chmod-findings').innerHTML = findings.length
        ? findings.map(f =>
            `<div class="notice ${f.level === 'high' ? 'bad' : f.level === 'warning' ? 'warn' : 'success'}">
                <b>${esc(f.title)}</b><br>${esc(f.detail)}
             </div>`
          ).join('')
        : '<div class="notice success"><b>No obvious permission red flags</b><br>The selected mode did not trigger the built-in heuristics.</div>';

    $('#chmod-symbolic-suggestion').textContent = symbolicSuggestion(mode);
}

export function renderChmod(app) {
    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>CHMOD Calculator / Parser</h2>
            <p class="small">Convert octal, symbolic and <span class="mono">ls -l</span> permissions locally.</p>
          </div>
          <span class="badge ok"></span>
        </div>

        <div class="grid two">
          <div class="card">
            <label for="chmod-input-type">Input format</label>
            <select id="chmod-input-type">
              <option value="octal">Octal (755 / 0644 / 4755)</option>
              <option value="symbolic">Symbolic (u=rwx,g=rx,o=rx)</option>
              <option value="ls">ls -l (-rwxr-xr-x)</option>
            </select>
          </div>

          <div class="card">
            <label for="chmod-object-type">Object type</label>
            <select id="chmod-object-type">
              <option value="-">Regular file (-)</option>
              <option value="d">Directory (d)</option>
              <option value="l">Symlink (l)</option>
              <option value="c">Character device (c)</option>
              <option value="b">Block device (b)</option>
              <option value="s">Socket (s)</option>
              <option value="p">FIFO / pipe (p)</option>
            </select>
          </div>
        </div>

        <div class="card">
          <label for="chmod-input">Permission value</label>
          <input id="chmod-input" type="text" value="755"
            placeholder="e.g. 755, u=rwx,g=rx,o=rx, or -rwxr-xr-x">
          <div class="row">
            <button class="btn primary" type="button" id="chmod-parse">Parse / Calculate</button>
            <button class="btn secondary" type="button" id="chmod-example">Example</button>
            <button class="btn secondary" type="button" id="chmod-clear">Clear</button>
          </div>
        </div>

        <div id="chmod-message" class="notice hidden" role="status"></div>

        <div class="card">
          <h2>Result</h2>
          <div class="grid three">
            <div class="stat"><span>Octal</span><strong id="chmod-octal">0755</strong></div>
            <div class="stat"><span>Symbolic</span><strong class="mono" id="chmod-symbolic">-rwxr-xr-x</strong></div>
            <div class="stat"><span>chmod command</span><strong class="mono" id="chmod-command">chmod 0755</strong></div>
          </div>

          <div class="grid three" style="margin-top:.75rem">
            <div class="stat"><span>Owner digit</span><strong id="chmod-owner">7</strong></div>
            <div class="stat"><span>Group digit</span><strong id="chmod-group">5</strong></div>
            <div class="stat"><span>Others digit</span><strong id="chmod-others">5</strong></div>
          </div>
        </div>

        <div class="card">
          <h2>Permission matrix</h2>
          <table>
            <thead><tr><th>Class</th><th>Read</th><th>Write</th><th>Execute</th></tr></thead>
            <tbody id="chmod-matrix"></tbody>
          </table>
        </div>

        <div class="card">
          <h2>Special bits</h2>
          <div class="grid three">
            <div class="stat"><span>Setuid</span><strong id="chmod-setuid">Disabled</strong></div>
            <div class="stat"><span>Setgid</span><strong id="chmod-setgid">Disabled</strong></div>
            <div class="stat"><span>Sticky</span><strong id="chmod-sticky">Disabled</strong></div>
          </div>
        </div>

        <div class="card">
          <h2>Security review</h2>
          <div id="chmod-findings"></div>
        </div>

        <div class="card">
          <h2>Symbolic suggestion</h2>
          <div class="mono" id="chmod-symbolic-suggestion"></div>
          <div class="small" style="margin-top:.5rem">This is a readable representation of the current complete mode; it is not intended to preserve every nuance of a relative chmod operation.</div>
        </div>
      </section>
    `;

    const $ = s => app.querySelector(s);
    const input = $('#chmod-input');
    const inputType = $('#chmod-input-type');
    const objectType = $('#chmod-object-type');
    const message = $('#chmod-message');

    function showMessage(text, kind = 'error') {
        message.textContent = text || '';
        message.className = text ? `notice ${kind}` : 'notice hidden';
    }

    function parseCurrent() {
        const type = objectType.value;
        const kind = inputType.value;
        let mode;

        if (kind === 'octal') {
            mode = parseOctal(input.value);
        } else if (kind === 'ls') {
            const parsed = parseLsPermission(input.value);
            mode = parsed.mode;
        } else {
            mode = parseSymbolic(input.value, 0, type);
        }

        renderDetails(app, mode, type);
        showMessage('Permission parsed successfully.', 'success');
    }

    $('#chmod-parse').addEventListener('click', () => {
        try {
            parseCurrent();
        } catch (e) {
            showMessage(e?.message || 'Could not parse the permission value.');
        }
    });

    input.addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            try { parseCurrent(); } catch (err) { showMessage(err?.message || 'Could not parse the permission value.'); }
        }
    });

    $('#chmod-example').addEventListener('click', () => {
        inputType.value = 'ls';
        input.value = '-rwsr-xr-t';
        objectType.value = '-';
        parseCurrent();
    });

    $('#chmod-clear').addEventListener('click', () => {
        input.value = '';
        showMessage('');
        renderDetails(app, 0o644, objectType.value);
    });

    inputType.addEventListener('change', () => {
        input.placeholder = {
            octal: 'e.g. 755, 0644, 4755',
            symbolic: 'e.g. u=rwx,g=rx,o=rx',
            ls: 'e.g. -rwxr-xr-x or drwxr-xr-t'
        }[inputType.value];
    });

    renderDetails(app, 0o755, '-');
}