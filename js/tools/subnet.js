import { $, escapeHtml } from '../utils.js';
export function renderSubnet(app) {
  app.innerHTML = `
    <section class="card">
      <h2>IP / subnet calculator</h2>

      <div class="grid-2">
        <div>
          <label for="cidr">CIDR</label>
          <input
            id="cidr"
            value="192.168.10.34/27"
            placeholder="192.168.10.34/27 or 2001:db8::1/64"
          >
        </div>

        <div class="row subnet-actions">
          <button class="btn primary" id="calc">Calculate</button>
        </div>
      </div>

      <div id="subResult" class="sub-result"></div>
    </section>
  `;

  $('#calc').onclick = calc;

  $('#cidr').onkeydown = e => {
    if (e.key === 'Enter') calc();
  };

  calc();
}

function ipv4ToInt(s) {
  const p = s.split('.');

  if (
    p.length !== 4 ||
    p.some(x => !/^[0-9]+$/.test(x) || +x > 255)
  ) {
    throw Error('Invalid IPv4');
  }

  return p.reduce((a, x) => (a * 256) + (+x), 0) >>> 0;
}

function intIp(n) {
  return [24, 16, 8, 0]
    .map(s => (n >>> s) & 255)
    .join('.');
}

function calc4(addr, p) {
  const ip = ipv4ToInt(addr);
  const mask = p === 0
    ? 0
    : (0xffffffff << (32 - p)) >>> 0;

  const net = (ip & mask) >>> 0;
  const broadcast = (net | (~mask >>> 0)) >>> 0;

  const hosts = p >= 31
    ? (p === 31 ? 2 : 1)
    : 2 ** (32 - p) - 2;

  return `
    <div class="grid">
      <div class="stat">
        <span>Network</span>
        <strong>${intIp(net)}</strong>
      </div>

      <div class="stat">
        <span>Broadcast</span>
        <strong>${intIp(broadcast)}</strong>
      </div>

      <div class="stat">
        <span>First address</span>
        <strong>${intIp(p >= 31 ? net : net + 1)}</strong>
      </div>

      <div class="stat">
        <span>Last address</span>
        <strong>${intIp(p >= 31 ? broadcast : broadcast - 1)}</strong>
      </div>

      <div class="stat">
        <span>Subnet mask</span>
        <strong>${intIp(mask)}</strong>
      </div>

      <div class="stat">
        <span>Host count</span>
        <strong>${hosts.toLocaleString()}</strong>
      </div>
    </div>
  `;
}

function expand6(s) {
  if (s.includes('::')) {
    const [l, r] = s.split('::');
    const L = l ? l.split(':') : [];
    const R = r ? r.split(':') : [];
    const n = 8 - L.length - R.length;

    if (n < 1) throw Error('Invalid IPv6');

    return [
      ...L,
      ...Array(n).fill('0'),
      ...R
    ].map(x => x || '0');
  }

  const a = s.split(':');

  if (a.length !== 8) throw Error('Invalid IPv6');

  return a;
}

function h6(a) {
  return a
    .map(x => x.toString(16).padStart(4, '0'))
    .join(':');
}

function calc6(addr, p) {
  const g = expand6(addr).map(x => {
    const n = parseInt(x, 16);

    if (!Number.isInteger(n) || n < 0 || n > 65535) {
      throw Error('Invalid IPv6');
    }

    return n;
  });

  const net = g.slice();
  const last = g.slice();

  for (let i = 0; i < 8; i++) {
    const start = i * 16;
    const keep = Math.max(0, Math.min(16, p - start));
    const mask = keep === 0
      ? 0
      : (0xffff << (16 - keep)) & 0xffff;

    net[i] &= mask;
    last[i] |= (~mask) & 0xffff;
  }

  return `
    <div class="grid">
      <div class="stat">
        <span>Network</span>
        <strong class="mono">${h6(net)}</strong>
      </div>

      <div class="stat">
        <span>Prefix</span>
        <strong>/${p}</strong>
      </div>

      <div class="stat">
        <span>First address</span>
        <strong class="mono">${h6(net)}</strong>
      </div>

      <div class="stat">
        <span>Last address</span>
        <strong class="mono">${h6(last)}</strong>
      </div>
    </div>
  `;
}

function calc() {
  try {
    const [addr, pText] = $('#cidr').value.trim().split('/');

    if (!addr || pText === undefined) {
      throw Error('Enter an address and prefix');
    }

    const p = Number(pText);

    if (addr.includes(':')) {
      if (!Number.isInteger(p) || p < 0 || p > 128) {
        throw Error('IPv6 prefix must be 0–128');
      }

      $('#subResult').innerHTML = calc6(addr, p);
    } else {
      if (!Number.isInteger(p) || p < 0 || p > 32) {
        throw Error('IPv4 prefix must be 0–32');
      }

      $('#subResult').innerHTML = calc4(addr, p);
    }
  } catch (e) {
    $('#subResult').innerHTML = `
      <div class="status danger">${escapeHtml(e.message)}</div>
    `;
  }
}