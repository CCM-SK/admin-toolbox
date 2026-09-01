import { $, escapeHtml, downloadText } from '../utils.js';

const WELL_KNOWN_SIDS = new Map([
  // Universal / generic identities
  ['S-1-0-0', 'NULL SID'],
  ['S-1-1-0', 'Everyone'],
  ['S-1-2-0', 'LOCAL'],
  ['S-1-2-1', 'CONSOLE LOGON'],
  ['S-1-3-0', 'CREATOR OWNER'],
  ['S-1-3-1', 'CREATOR GROUP'],
  ['S-1-3-2', 'OWNER SERVER'],
  ['S-1-3-3', 'GROUP SERVER'],
  ['S-1-3-4', 'OWNER RIGHTS'],
  ['S-1-4-0', 'NON-UNIQUE'],

  // NT AUTHORITY
  ['S-1-5-1', 'DIALUP'],
  ['S-1-5-2', 'NETWORK'],
  ['S-1-5-3', 'BATCH'],
  ['S-1-5-4', 'INTERACTIVE'],
  ['S-1-5-5-0-X', 'LOGON SESSION'],
  ['S-1-5-6', 'SERVICE'],
  ['S-1-5-7', 'ANONYMOUS LOGON'],
  ['S-1-5-8', 'PROXY'],
  ['S-1-5-9', 'ENTERPRISE DOMAIN CONTROLLERS'],
  ['S-1-5-10', 'SELF'],
  ['S-1-5-11', 'Authenticated Users'],
  ['S-1-5-12', 'RESTRICTED CODE'],
  ['S-1-5-13', 'TERMINAL SERVER USER'],
  ['S-1-5-14', 'REMOTE INTERACTIVE LOGON'],
  ['S-1-5-17', 'IUSR'],
  ['S-1-5-18', 'NT AUTHORITY\\SYSTEM'],
  ['S-1-5-19', 'NT AUTHORITY\\LOCAL SERVICE'],
  ['S-1-5-20', 'NT AUTHORITY\\NETWORK SERVICE'],

  // Windows local-account / authentication-related well-known SIDs
  ['S-1-5-113', 'NT AUTHORITY\\Local account'],
  ['S-1-5-114', 'NT AUTHORITY\\Local account and member of Administrators group'],

  // BUILTIN groups
  ['S-1-5-32-544', 'BUILTIN\\Administrators'],
  ['S-1-5-32-545', 'BUILTIN\\Users'],
  ['S-1-5-32-546', 'BUILTIN\\Guests'],
  ['S-1-5-32-547', 'BUILTIN\\Power Users'],
  ['S-1-5-32-548', 'BUILTIN\\Account Operators'],
  ['S-1-5-32-549', 'BUILTIN\\Server Operators'],
  ['S-1-5-32-550', 'BUILTIN\\Print Operators'],
  ['S-1-5-32-551', 'BUILTIN\\Backup Operators'],
  ['S-1-5-32-552', 'BUILTIN\\Replicator'],
  ['S-1-5-32-554', 'BUILTIN\\Pre-Windows 2000 Compatible Access'],
  ['S-1-5-32-555', 'BUILTIN\\Remote Desktop Users'],
  ['S-1-5-32-556', 'BUILTIN\\Network Configuration Operators'],
  ['S-1-5-32-557', 'BUILTIN\\Incoming Forest Trust Builders'],
  ['S-1-5-32-558', 'BUILTIN\\Performance Monitor Users'],
  ['S-1-5-32-559', 'BUILTIN\\Performance Log Users'],
  ['S-1-5-32-560', 'BUILTIN\\Windows Authorization Access Group'],
  ['S-1-5-32-561', 'BUILTIN\\Terminal Server License Servers'],
  ['S-1-5-32-562', 'BUILTIN\\Distributed COM Users'],
  ['S-1-5-32-568', 'BUILTIN\\IIS_IUSRS'],
  ['S-1-5-32-569', 'BUILTIN\\Cryptographic Operators'],
  ['S-1-5-32-573', 'BUILTIN\\Event Log Readers'],
  ['S-1-5-32-574', 'BUILTIN\\Certificate Service DCOM Access'],
  ['S-1-5-32-575', 'BUILTIN\\RDS Remote Access Servers'],
  ['S-1-5-32-576', 'BUILTIN\\RDS Endpoint Servers'],
  ['S-1-5-32-577', 'BUILTIN\\RDS Management Servers'],
  ['S-1-5-32-578', 'BUILTIN\\Hyper-V Administrators'],
  ['S-1-5-32-579', 'BUILTIN\\Access Control Assistance Operators'],
  ['S-1-5-32-580', 'BUILTIN\\Remote Management Users'],
  ['S-1-5-32-581', 'BUILTIN\\System Managed Accounts Group'],
  ['S-1-5-32-582', 'BUILTIN\\Storage Replica Administrators'],
  ['S-1-5-80-0', 'NT SERVICE\\ALL SERVICES']
]);

const DOMAIN_RIDS = new Map([
  [500, 'Administrator'],
  [501, 'Guest'],
  [502, 'KRBTGT'],
  [512, 'Domain Admins'],
  [513, 'Domain Users'],
  [514, 'Domain Guests'],
  [515, 'Domain Computers'],
  [516, 'Domain Controllers'],
  [517, 'Cert Publishers'],
  [518, 'Schema Admins'],
  [519, 'Enterprise Admins'],
  [520, 'Group Policy Creator Owners'],
  [521, 'Read-only Domain Controllers'],
  [522, 'Cloneable Domain Controllers'],
  [525, 'Protected Users'],
  [526, 'Key Admins'],
  [527, 'Enterprise Key Admins'],
  [553, 'RAS and IAS Servers'],
  [582, 'Storage Replica Administrators']
]);

const BUILTIN_RIDS = new Map([
  [544, 'Administrators'],
  [545, 'Users'],
  [546, 'Guests'],
  [547, 'Power Users'],
  [548, 'Account Operators'],
  [549, 'Server Operators'],
  [550, 'Print Operators'],
  [551, 'Backup Operators'],
  [552, 'Replicator'],
  [554, 'Pre-Windows 2000 Compatible Access'],
  [555, 'Remote Desktop Users'],
  [556, 'Network Configuration Operators'],
  [557, 'Incoming Forest Trust Builders'],
  [558, 'Performance Monitor Users'],
  [559, 'Performance Log Users'],
  [560, 'Windows Authorization Access Group'],
  [561, 'Terminal Server License Servers'],
  [562, 'Distributed COM Users'],
  [568, 'IIS_IUSRS'],
  [569, 'Cryptographic Operators'],
  [573, 'Event Log Readers'],
  [574, 'Certificate Service DCOM Access'],
  [575, 'RDS Remote Access Servers'],
  [576, 'RDS Endpoint Servers'],
  [577, 'RDS Management Servers'],
  [578, 'Hyper-V Administrators'],
  [579, 'Access Control Assistance Operators'],
  [580, 'Remote Management Users'],
  [581, 'System Managed Accounts Group'],
  [582, 'Storage Replica Administrators']
]);

export function renderIdentity(app) {
  app.innerHTML = `
    <section class="card">
      <h2>SID / GUID / identity decoder</h2>
      <p class="small">
        Recognizes Windows SIDs, GUIDs, UUID byte strings, and common GUID representations.
        Processing is entirely local.
      </p>

      <label for="identityInput">Value</label>
      <textarea
        id="identityInput"
        class="mono"
        style="min-height:180px"
        placeholder="Examples:
S-1-5-21-1111111111-2222222222-3333333333-1107
S-1-5-18
S-1-5-32-544
550e8400-e29b-41d4-a716-446655440000
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ></textarea>

      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="identityDecode">Decode</button>
        <button class="btn" id="identityClear">Clear</button>
        <button class="btn" id="identityExport">Export result</button>
      </div>
    </section>

    <section class="card" id="identityResult" hidden></section>
  `;

  let last = null;

  $('#identityDecode').onclick = () => {
    last = decode($('#identityInput').value.trim());
    render(last);
  };

  $('#identityClear').onclick = () => {
    $('#identityInput').value = '';
    $('#identityResult').hidden = true;
    last = null;
    $('#identityInput').focus();
  };

  $('#identityExport').onclick = () => {
    if (!last) {
      last = decode($('#identityInput').value.trim());
    }

    downloadText(
      'identity-decoder.json',
      JSON.stringify(last, null, 2),
      'application/json;charset=utf-8'
    );
  };

  function decode(v) {
    const out = {
      input: v,
      matches: []
    };

    if (!v) {
      return out;
    }

    const sid = parseSid(v);
    if (sid) {
      out.matches.push(sid);
    }

    const guid = parseGuid(v);
    if (guid) {
      out.matches.push(guid);
    }

    const bytes = parseBytes(v);

    if (bytes && bytes.length === 16) {
      const standard = bytesToGuid(bytes, false);
      const mixed = bytesToGuid(bytes, true);

      out.matches.push({
        type: 'GUID byte string',
        standardGuid: standard,
        littleEndianGuid: mixed,
        rawBytes: Array.from(bytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ')
      });
    }

    if (!out.matches.length) {
      out.error = 'No recognized SID/GUID representation.';
    }

    return out;
  }

  function parseSid(v) {
    const m = v.match(/^S-(\d+)-([\dA-Fa-fx]+)((?:-\d+)+)$/);

    if (!m) {
      return null;
    }

    let revision;

    try {
      revision = Number(m[1]);
      if (!Number.isSafeInteger(revision)) {
        return null;
      }
    } catch {
      return null;
    }

    let authority;

    try {
      authority = BigInt(
        m[2].toLowerCase().startsWith('0x')
          ? m[2]
          : m[2]
      );
    } catch {
      return null;
    }

    const subs = m[3]
      .slice(1)
      .split('-')
      .map(Number);

    if (
      subs.some(
        x => !Number.isSafeInteger(x) || x < 0
      )
    ) {
      return null;
    }

    const rid = subs.at(-1);

    const sid = `S-${revision}-${authority.toString()}-${subs.join('-')}`;
    const exactMeaning = WELL_KNOWN_SIDS.get(sid) || null;
    const contextual = classifySidContext(
      revision,
      authority,
      subs,
      rid
    );

    return {
      type: 'Windows SID',
      sid,
      revision,
      identifierAuthority: authority.toString(),
      subAuthorities: subs,
      relativeId: rid,
      wellKnownMeaning: exactMeaning,
      ridMeaning: contextual?.meaning || null,
      sidContext: contextual?.context || null,
      displayName:
        exactMeaning ||
        contextual?.displayName ||
        null,

      resolutionSource:
        exactMeaning
          ? 'local-static-sid-map'
          : contextual
            ? 'local-contextual-rid-map'
            : null,

      domainIdentifier: isDomainSid(subs)
        ? subs.slice(1, -1)
        : [],

      isWellKnown:
        Boolean(exactMeaning),

      isContextual:
        Boolean(contextual && !exactMeaning)
    };
  }

  function classifySidContext(
    revision,
    authority,
    subs,
    rid
  ) {
    if (revision !== 1 || authority !== 5) {
      return null;
    }
    if (subs.length === 2 && subs[0] === 32) {
      const meaning = BUILTIN_RIDS.get(rid);

      if (!meaning) {
        return null;
      }

      return {
        context: 'BUILTIN local group',
        meaning,
        displayName: `BUILTIN\\${meaning}`
      };
    }

    if (
      subs.length === 5 &&
      subs[0] === 21
    ) {
      const meaning = DOMAIN_RIDS.get(rid);

      if (!meaning) {
        return {
          context: 'Domain SID',
          meaning: null,
          displayName: null
        };
      }

      return {
        context: 'Domain account/group',
        meaning,
        displayName: `DOMAIN\\${meaning}`
      };
    }

    return null;
  }

  function isDomainSid(subs) {
    return (
      subs.length >= 5 &&
      subs[0] === 21
    );
  }

  function parseGuid(v) {
    const s = v.trim().replace(/[{}]/g, '');

    if (
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(
        s
      )
    ) {
      return null;
    }

    const hex = s
      .replaceAll('-', '')
      .toLowerCase();

    const bytes = hex
      .match(/../g)
      .map(x => parseInt(x, 16));

    return {
      type: 'GUID / UUID',
      canonical: s.toLowerCase(),
      uppercase: s.toUpperCase(),
      braced: `{${s.toUpperCase()}}`,
      hexBytes: bytes
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' '),
      registryByteOrder: toMixedEndian(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ')
    };
  }

  function parseBytes(v) {
    const compact = v
      .replace(/0x/gi, '')
      .replace(/[\s,;:-]/g, '');

    if (
      !/^[0-9a-fA-F]+$/.test(compact) ||
      compact.length % 2
    ) {
      return null;
    }

    const out = new Uint8Array(compact.length / 2);

    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(
        compact.slice(i * 2, i * 2 + 2),
        16
      );
    }

    return out;
  }

  function bytesToGuid(b, little) {
    const x = little
      ? toMixedEndian([...b])
      : [...b];

    const h = x
      .map(z => z.toString(16).padStart(2, '0'))
      .join('');

    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }

  function toMixedEndian(b) {
    return [
      b[3],
      b[2],
      b[1],
      b[0],
      b[5],
      b[4],
      b[7],
      b[6],
      ...b.slice(8)
    ];
  }

  function render(r) {
    const el = $('#identityResult');
    el.hidden = false;

    if (r.error) {
      el.innerHTML = `
        <p class="status warn">
          ${escapeHtml(r.error)}
        </p>
      `;
      return;
    }

    el.innerHTML = r.matches
      .map(
        m => `
          <div
            class="card"
            style="box-shadow:none;margin:0 0 12px;padding:14px"
          >
            <h3>${escapeHtml(m.type)}</h3>
            <pre class="mono">${escapeHtml(
              JSON.stringify(m, null, 2)
            )}</pre>
          </div>
        `
      )
      .join('');
  }
}