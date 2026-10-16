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
const ACE_TYPES = {
  A: { name: 'Access Allowed', description: 'Grants the listed rights to the trustee.' },
  D: { name: 'Access Denied', description: 'Denies the listed rights to the trustee.' },
  OA: { name: 'Object Access Allowed', description: 'Access-allowed ACE that applies only to a specific object/property type (object_guid) and/or only propagates to a specific child object type (inherit_object_guid).' },
  OD: { name: 'Object Access Denied', description: 'Access-denied ACE that applies only to a specific object/property type and/or only propagates to a specific child object type.' },
  AU: { name: 'System Audit', description: 'Audit ACE (used in a SACL): generates an audit entry when the listed rights are used, per the SA/FA flags.' },
  AL: { name: 'System Alarm', description: 'Reserved; alarm ACEs are not implemented by current Windows versions.' },
  OU: { name: 'Object System Audit', description: 'Object-specific audit ACE (used in a SACL), scoped to a particular object/property type.' },
  OL: { name: 'Object System Alarm', description: 'Reserved; object-specific alarm ACEs are not implemented by current Windows versions.' },
  ML: { name: 'Mandatory Label', description: 'Sets the Windows Integrity Level of the object (used in a SACL). The rights field encodes the no-read-up/no-write-up/no-execute-up policy, not file-style permissions.' },
  XA: { name: 'Callback Access Allowed', description: 'Access-allowed ACE with an attached conditional expression (resource_attribute field) that must also evaluate true.' },
  XD: { name: 'Callback Access Denied', description: 'Access-denied ACE with an attached conditional expression that must also evaluate true.' },
  RA: { name: 'Resource Attribute', description: 'Stores a Central Access Policy resource attribute (e.g. a classification tag) rather than a grant/deny rule.' },
  SP: { name: 'Scoped Policy ID', description: 'References a Central Access Policy applied to the object.' },
  XU: { name: 'Callback System Audit', description: 'Audit ACE with an attached conditional expression.' },
  ZA: { name: 'Callback Object Access Allowed', description: 'Object-specific access-allowed ACE with an attached conditional expression.' },
  TL: { name: 'Process Trust Label', description: 'Used for Windows process/protected-process trust-level labelling, not user access.' },
  FL: { name: 'Access Filter', description: 'Access filter ACE used by newer Windows access-control features.' }
};
const ACE_FLAGS = {
  CI: { name: 'Container Inherit', description: 'Child containers inherit this ACE.' },
  OI: { name: 'Object Inherit', description: 'Child (non-container) objects inherit this ACE.' },
  NP: { name: 'No Propagate', description: 'Inheritance stops after the immediate children; it does not propagate further down the tree.' },
  IO: { name: 'Inherit Only', description: 'The ACE does not apply to this object itself, only to objects that inherit it.' },
  ID: { name: 'Inherited', description: 'This ACE was itself inherited from a parent container, rather than set directly.' },
  SA: { name: 'Audit Success', description: 'Generate an audit entry when the access succeeds (SACL only).' },
  FA: { name: 'Audit Failure', description: 'Generate an audit entry when the access is attempted but denied (SACL only).' },
  TP: { name: 'Trust Protected Filter', description: 'Used with process trust-label ACEs.' },
  CR: { name: 'Critical', description: 'Marks the ACE as critical; some APIs refuse to silently drop a critical ACE.' }
};
const RIGHTS = {
//Generic
  GA: { name: 'Generic All', category: 'Generic', description: 'Full control, mapped to the object type\u2019s own all-access right.' },
  GR: { name: 'Generic Read', category: 'Generic', description: 'Mapped to the object type\u2019s own read right(s).' },
  GW: { name: 'Generic Write', category: 'Generic', description: 'Mapped to the object type\u2019s own write right(s).' },
  GX: { name: 'Generic Execute', category: 'Generic', description: 'Mapped to the object type\u2019s own execute right(s).' },
//Standard
  RC: { name: 'Read Control', category: 'Standard', description: 'Read the security descriptor itself (owner, group, DACL) excluding the SACL.' },
  SD: { name: 'Delete', category: 'Standard', description: 'Delete the object.' },
  WD: { name: 'Write DAC', category: 'Standard', description: 'Modify the object\u2019s DACL, i.e. change its permissions.' },
  WO: { name: 'Write Owner', category: 'Standard', description: 'Change the object\u2019s owner - the new owner can then grant themselves anything.' },
//Directory service object
  RP: { name: 'Read Property', category: 'Directory Service', description: 'Read one or more attributes of an Active Directory object.' },
  WP: { name: 'Write Property', category: 'Directory Service', description: 'Write one or more attributes of an Active Directory object.' },
  CC: { name: 'Create Child', category: 'Directory Service', description: 'Create child objects of a given class under this object.' },
  DC: { name: 'Delete Child', category: 'Directory Service', description: 'Delete child objects of a given class under this object.' },
  LC: { name: 'List Children', category: 'Directory Service', description: 'List (enumerate) the object\u2019s child objects.' },
  SW: { name: 'Self Write', category: 'Directory Service', description: 'Add/remove itself as a member of the object (validated write, e.g. group self-membership).' },
  LO: { name: 'List Object', category: 'Directory Service', description: 'See the object at all when object-visibility filtering is in effect.' },
  DT: { name: 'Delete Tree', category: 'Directory Service', description: 'Delete the object together with all of its children in one operation.' },
  CR: { name: 'Control Access', category: 'Directory Service', description: 'Perform an extended right identified by the ACE\u2019s object_guid, e.g. Change Password or DS-Replication-Get-Changes.' },
//File
  FA: { name: 'File All', category: 'File', description: 'Full control over the file or folder (FILE_GENERIC_ALL).' },
  FR: { name: 'File Read', category: 'File', description: 'Read access to the file or folder (FILE_GENERIC_READ).' },
  FW: { name: 'File Write', category: 'File', description: 'Write access to the file or folder (FILE_GENERIC_WRITE).' },
  FX: { name: 'File Execute', category: 'File', description: 'Execute/traverse access to the file or folder (FILE_GENERIC_EXECUTE).' },
//Registry
  KA: { name: 'Key All Access', category: 'Registry', description: 'Full control over the registry key.' },
  KR: { name: 'Key Read', category: 'Registry', description: 'Read access to the registry key (KEY_READ).' },
  KW: { name: 'Key Write', category: 'Registry', description: 'Write access to the registry key (KEY_WRITE).' },
  KX: { name: 'Key Execute', category: 'Registry', description: 'Execute access to the registry key (functionally the same as KEY_READ).' },
//Mandatory label
  NR: { name: 'No Read Up', category: 'Mandatory Label', description: 'Processes running at a lower integrity level than this label cannot read the object.' },
  NW: { name: 'No Write Up', category: 'Mandatory Label', description: 'Processes running at a lower integrity level than this label cannot write to the object. This is the rule that normally enforces integrity-level protection.' },
  NX: { name: 'No Execute Up', category: 'Mandatory Label', description: 'Processes running at a lower integrity level than this label cannot execute the object.' }
};
const DACL_SACL_FLAGS = {
  P: { name: 'Protected', description: 'The ACL is protected from being overwritten by inheritable ACEs from a parent container.' },
  AR: { name: 'Auto-Inherit Required', description: 'Automatic propagation of inheritable ACEs from the parent is required.' },
  AI: { name: 'Auto-Inherited', description: 'The ACL has already had inheritable ACEs propagated into it by the system.' },
  NO_ACCESS_CONTROL: { name: 'Null ACL', description: 'There is no ACL at all (as opposed to an empty one). A null DACL means no access check is performed - everyone has full access.' }
};
const RESOURCE_ATTR_TYPES = {
  TI: 'Signed integer',
  TU: 'Unsigned integer',
  TS: 'Wide string',
  TD: 'SID',
  TX: 'Octet string',
  TB: 'Boolean'
};
const COMMON_OBJECT_GUIDS = {
  'ab721a53-1e2f-11d0-9819-00aa0040529b': { name: 'User-Change-Password', description: 'Change your own password (the caller must supply the current password).' },
  '00299570-246d-11d0-a768-00aa006e0529': { name: 'User-Force-Change-Password', description: 'Reset another user\u2019s password without knowing the current one.' },
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': { name: 'DS-Replication-Get-Changes', description: 'Request replicated directory changes from a domain controller. Sensitive: part of what DCSync abuses.' },
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': { name: 'DS-Replication-Get-Changes-All', description: 'Request replicated secret data (including password hashes) from a domain controller. Highly sensitive: this is the key right abused by DCSync-style attacks.' },
  '89e95b76-444d-4c62-991a-0facbeda640c': { name: 'DS-Replication-Get-Changes-In-Filtered-Set', description: 'Request a filtered subset of replicated directory changes.' }
};
const SID_ALIASES = {
  AA: { name: 'Access Control Assistance Operators', sid: 'S-1-5-32-579' },
  AC: { name: 'All App Packages', description: 'Every app running in an app-package (UWP/sandboxed) context.', sid: 'S-1-15-2-1' },
  AN: { name: 'Anonymous Logon', sid: 'S-1-5-7' },
  AO: { name: 'Account Operators', sid: 'S-1-5-32-548' },
  AP: { name: 'Protected Users', domainRelative: true },
  AU: { name: 'Authenticated Users', sid: 'S-1-5-11' },
  BA: { name: 'Builtin Administrators', sid: 'S-1-5-32-544' },
  BG: { name: 'Builtin Guests', sid: 'S-1-5-32-546' },
  BO: { name: 'Backup Operators', sid: 'S-1-5-32-551' },
  BU: { name: 'Builtin Users', sid: 'S-1-5-32-545' },
  CA: { name: 'Certificate Publishers', domainRelative: true, rid: 517 },
  CD: { name: 'Certification Authority DCOM Access Group', sid: 'S-1-5-32-574' },
  CG: { name: 'Creator Group', description: 'Placeholder replaced with the creating user\u2019s primary group SID when the ACE is inherited.', sid: 'S-1-3-1' },
  CN: { name: 'Cloneable Domain Controllers', domainRelative: true, rid: 522 },
  CO: { name: 'Creator Owner', description: 'Placeholder replaced with the creating user\u2019s SID when the ACE is inherited.', sid: 'S-1-3-0' },
  CY: { name: 'Cryptographic Operators', sid: 'S-1-5-32-569' },
  DA: { name: 'Domain Admins', domainRelative: true, rid: 512 },
  DC: { name: 'Domain Computers', domainRelative: true, rid: 515 },
  DD: { name: 'Domain Controllers', domainRelative: true, rid: 516 },
  DG: { name: 'Domain Guests', domainRelative: true, rid: 514 },
  DU: { name: 'Domain Users', domainRelative: true, rid: 513 },
  EA: { name: 'Enterprise Admins', domainRelative: true, rid: 519 },
  ED: { name: 'Enterprise Domain Controllers', sid: 'S-1-5-9' },
  EK: { name: 'Enterprise Key Admins', domainRelative: true, rid: 527 },
  ER: { name: 'Event Log Readers', sid: 'S-1-5-32-573' },
  ES: { name: 'RDS Endpoint Servers', sid: 'S-1-5-32-576' },
  HA: { name: 'Hyper-V Administrators', sid: 'S-1-5-32-578' },
  HI: { name: 'High Mandatory Integrity Level', sid: 'S-1-16-12288' },
  HO: { name: 'User-Mode Hardware Operators', sid: 'S-1-5-32-584' },
  IS: { name: 'IIS/Anonymous Internet Users', sid: 'S-1-5-32-568' },
  IU: { name: 'Interactively Logged-on User', sid: 'S-1-5-4' },
  KA: { name: 'Key Admins', domainRelative: true, rid: 526 },
  LA: { name: 'Local Administrator Account', domainRelative: true, rid: 500 },
  LG: { name: 'Local Guest Account', domainRelative: true, rid: 501 },
  LS: { name: 'Local Service Account', sid: 'S-1-5-19' },
  LU: { name: 'Performance Log Users', sid: 'S-1-5-32-559' },
  LW: { name: 'Low Mandatory Integrity Level', sid: 'S-1-16-4096' },
  ME: { name: 'Medium Mandatory Integrity Level', sid: 'S-1-16-8192' },
  MP: { name: 'Medium-Plus Mandatory Integrity Level', sid: 'S-1-16-8448' },
  MU: { name: 'Performance Monitor Users', sid: 'S-1-5-32-558' },
  NO: { name: 'Network Configuration Operators', sid: 'S-1-5-32-556' },
  NS: { name: 'Network Service Account', sid: 'S-1-5-20' },
  NU: { name: 'Network Logon User', sid: 'S-1-5-2' },
  OW: { name: 'Owner Rights', description: 'Placeholder representing the current owner; lets an ACL grant the owner different rights than other principals get.', sid: 'S-1-3-4' },
  PA: { name: 'Group Policy Creator Owners', domainRelative: true, rid: 520 },
  PO: { name: 'Printer Operators', sid: 'S-1-5-32-550' },
  PS: { name: 'Principal Self', description: 'Placeholder replaced with the object\u2019s own SID; used so an object can be granted rights over itself.', sid: 'S-1-5-10' },
  PU: { name: 'Power Users', sid: 'S-1-5-32-547' },
  RA: { name: 'RDS Remote Access Servers', description: 'Not to be confused with the "RA" ACE type (Resource Attribute) in the type field.' },
  RC: { name: 'Restricted Code', description: 'A restricted token created with CreateRestrictedToken. Not to be confused with the "RC" access right (Read Control).', sid: 'S-1-5-12' },
  RD: { name: 'Remote Desktop/Terminal Server Users', sid: 'S-1-5-32-555' },
  RE: { name: 'Replicator', sid: 'S-1-5-32-552' },
  RM: { name: 'RMS Service Operators', description: 'Legacy (Windows Vista-era) Rights Management Services operators group.' },
  RO: { name: 'Enterprise Read-only Domain Controllers', domainRelative: true, rid: 498 },
  RS: { name: 'RAS Servers Group', sid: 'S-1-5-32-553' },
  RU: { name: 'Pre-Windows 2000 Compatible Access', sid: 'S-1-5-32-554' },
  SA: { name: 'Schema Admins', domainRelative: true, rid: 518 },
  SH: { name: 'OpenSSH Users', sid: 'S-1-5-32-585' },
  SI: { name: 'System Mandatory Integrity Level', sid: 'S-1-16-16384' },
  SO: { name: 'Server Operators', sid: 'S-1-5-32-549' },
  SU: { name: 'Service Logon User', sid: 'S-1-5-6' },
  SY: { name: 'Local System', sid: 'S-1-5-18' },
  UD: { name: 'User-Mode Drivers', description: 'User-mode driver host account.' },
  WD: { name: 'Everyone', sid: 'S-1-1-0' },
  WR: { name: 'Write-Restricted Code', sid: 'S-1-5-33' }
};
const DOMAIN_RELATIVE_RID_NAMES = {
  498: 'Enterprise Read-only Domain Controllers',
  500: 'built-in Administrator account',
  501: 'built-in Guest account',
  512: 'Domain Admins',
  513: 'Domain Users',
  514: 'Domain Guests',
  515: 'Domain Computers',
  516: 'Domain Controllers',
  517: 'Cert Publishers',
  518: 'Schema Admins',
  519: 'Enterprise Admins',
  520: 'Group Policy Creator Owners',
  522: 'Cloneable Domain Controllers',
  526: 'Key Admins',
  527: 'Enterprise Key Admins'
};
function splitOutsideParens(str, delimiter) {
  const parts = [];
  let depth = 0;
  let current = '';
  for (const ch of str) {
    if (ch === '(') depth++;
    if (ch === ')') depth--;
    if (ch === delimiter && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}
function extractParenGroups(str) {
  const groups = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (ch === '(') {
      if (depth === 0) start = i + 1;
      depth++;
    } else if (ch === ')') {
      depth--;
      if (depth === 0 && start !== -1) {
        groups.push(str.slice(start, i));
        start = -1;
      }
    }
  }
  return groups;
}
function splitTopLevelSections(text) {
  const sections = {};
  let currentKey = null;
  let currentStart = 0;
  let depth = 0;
  const n = text.length;
  const flush = endIdx => {
    if (currentKey) {
      sections[currentKey] = (sections[currentKey] || '') + text.slice(currentStart, endIdx);
    }
  };
  let i = 0;
  while (i < n) {
    const ch = text[i];
    if (ch === '(') { depth++; i++; continue; }
    if (ch === ')') { depth--; i++; continue; }
    if (depth === 0 && 'OGDS'.includes(ch) && text[i + 1] === ':') {
      flush(i);
      currentKey = ch;
      currentStart = i + 2;
      i += 2;
      continue;
    }
    i++;
  }
  flush(n);
  return sections;
}
function decodeAceType(code) {
  return ACE_TYPES[code] || null;
}
function decodeAceFlags(flagsStr) {
  const result = [];
  let rest = flagsStr;
  while (rest.length) {
    const token = rest.slice(0, 2);
    if (ACE_FLAGS[token]) {
      result.push({ code: token, ...ACE_FLAGS[token] });
      rest = rest.slice(2);
    } else {
      result.push({ code: rest, name: 'Unrecognized', description: 'Unrecognized ACE flag token(s).' });
      break;
    }
  }
  return result;
}
function decodeRights(rightsStr) {
  if (!rightsStr) {
    return { isHex: false, isEmpty: true, tokens: [] };
  }
  if (/^0x[0-9a-fA-F]+$/.test(rightsStr)) {
    return { isHex: true, hex: rightsStr, value: parseInt(rightsStr, 16), tokens: [] };
  }
  const result = [];
  let rest = rightsStr;
  while (rest.length) {
    const token = rest.slice(0, 2);
    if (RIGHTS[token]) {
      result.push({ code: token, ...RIGHTS[token] });
      rest = rest.slice(2);
    } else {
      result.push({ code: rest, name: 'Unrecognized', category: '', description: 'Unrecognized access-right token(s).' });
      break;
    }
  }
  return { isHex: false, isEmpty: false, tokens: result };
}
function parseControlFlags(flagsStr) {
  if (!flagsStr) return [];
  if (flagsStr === 'NO_ACCESS_CONTROL') {
    return [{ code: 'NO_ACCESS_CONTROL', ...DACL_SACL_FLAGS.NO_ACCESS_CONTROL }];
  }
  const found = [];
  let rest = flagsStr;
  while (rest.length) {
    if (rest.startsWith('AR')) { found.push({ code: 'AR', ...DACL_SACL_FLAGS.AR }); rest = rest.slice(2); }
    else if (rest.startsWith('AI')) { found.push({ code: 'AI', ...DACL_SACL_FLAGS.AI }); rest = rest.slice(2); }
    else if (rest.startsWith('P')) { found.push({ code: 'P', ...DACL_SACL_FLAGS.P }); rest = rest.slice(1); }
    else {
      found.push({ code: rest, name: 'Unrecognized', description: 'Unrecognized ACL control flag token.' });
      break;
    }
  }
  return found;
}
function describeLiteralSid(sid) {
  const parts = sid.split('-');
  if (parts.length === 8 && parts[2] === '5' && parts[3] === '21') {
    const rid = Number(parts[7]);
    const known = DOMAIN_RELATIVE_RID_NAMES[rid];
    return `Domain-relative SID (S-1-5-21-\u2026). RID ${rid}${known ? ` - commonly ${known}` : ''}.`;
  }
  if (parts.length === 5 && parts[2] === '5' && parts[3] === '32') {
    return `Builtin-domain SID (S-1-5-32), RID ${parts[4]}.`;
  }
  return null;
}
function decodeSid(rawToken) {
  const token = (rawToken || '').trim();
  if (!token) return { kind: 'empty' };
  if (/^S-1-/i.test(token)) {
    return { kind: 'literal', sid: token, note: describeLiteralSid(token) };
  }
  const alias = SID_ALIASES[token.toUpperCase()];
  if (alias) {
    return { kind: 'alias', code: token.toUpperCase(), ...alias };
  }
  return { kind: 'unknown', raw: token };
}
function sidDisplay(sidInfo) {
  switch (sidInfo.kind) {
    case 'empty':
      return '(none)';
    case 'alias':
      return `${sidInfo.code} - ${sidInfo.name}${sidInfo.sid ? ` (${sidInfo.sid})` : sidInfo.domainRelative ? ` (domain-relative${sidInfo.rid ? `, RID ${sidInfo.rid}` : ''})` : ''}`;
    case 'literal':
      return sidInfo.note ? `${sidInfo.sid} - ${sidInfo.note}` : sidInfo.sid;
    default:
      return `${sidInfo.raw} (not a recognized SDDL alias or S-1-\u2026 SID)`;
  }
}
function rightsDisplay(rightsResult) {
  if (rightsResult.isEmpty) return '(none)';
  if (rightsResult.isHex) return `${rightsResult.hex} (raw access mask, 0x${rightsResult.value.toString(16)})`;
  return rightsResult.tokens.map(t => `${t.code} (${t.name})`).join(', ');
}
function flagsDisplay(flagList) {
  if (!flagList.length) return '(none)';
  return flagList.map(f => `${f.code} (${f.name})`).join(', ');
}
function parseSingleAce(inner) {
  const fields = splitOutsideParens(inner, ';').map(f => f.trim());
  const [type = '', flagsRaw = '', rightsRaw = '', objectGuid = '', inheritObjectGuid = '', sidRaw = '', ...rest] = fields;
  return {
    raw: `(${inner})`,
    type,
    flagsRaw,
    rightsRaw,
    objectGuid,
    inheritObjectGuid,
    sidRaw,
    extra: rest.join(';'),
    fieldCount: fields.length
  };
}
function parseAceList(str) {
  return extractParenGroups(str).map(parseSingleAce);
}
function parseAclSection(raw) {
  if (raw === undefined) return null;
  const firstParen = raw.indexOf('(');
  const flagsRaw = (firstParen === -1 ? raw : raw.slice(0, firstParen)).trim();
  const acesRaw = firstParen === -1 ? '' : raw.slice(firstParen);
  return {
    flags: parseControlFlags(flagsRaw),
    flagsRaw,
    aces: parseAceList(acesRaw),
    isNull: flagsRaw === 'NO_ACCESS_CONTROL'
  };
}
function parseSddl(raw) {
  const text = raw.replace(/\s+/g, '');
  if (!text) return { mode: 'empty' };
  const hasAnyMarker = /(^|[^A-Za-z])[OGDS]:/.test(text) || /^[OGDS]:/.test(text);
  if (!hasAnyMarker) {
    return { mode: 'unrecognized' };
  }
  const sections = splitTopLevelSections(text);
  return {
    mode: 'parsed',
    owner: sections.O !== undefined ? decodeSid(sections.O) : null,
    group: sections.G !== undefined ? decodeSid(sections.G) : null,
    dacl: parseAclSection(sections.D),
    sacl: parseAclSection(sections.S),
    hasD: sections.D !== undefined,
    hasS: sections.S !== undefined
  };
}
const BROAD_PRINCIPALS = new Set(['WD', 'AU', 'BU', 'AC']);
const TAKEOVER_RIGHTS = new Set(['GA', 'WD', 'WO']);
const SACL_ONLY_TYPES = new Set(['AU', 'AL', 'OU', 'OL', 'ML']);
const DACL_ONLY_TYPES = new Set(['A', 'D', 'OA', 'OD', 'XA', 'XD', 'ZA']);
function analyzeAce(ace, aclKind) {
  const findings = [];
  const typeInfo = decodeAceType(ace.type);
  if (!typeInfo) {
    findings.push({
      level: 'danger',
      title: `Unrecognized ACE type "${ace.type}"`,
      detail: 'This does not match any known Sddl.h ace_type string. Check for typos or a newer/undocumented ACE type.'
    });
  } else if (aclKind === 'dacl' && SACL_ONLY_TYPES.has(ace.type)) {
    findings.push({
      level: 'warn',
      title: `${typeInfo.name} ACE found in the DACL`,
      detail: 'This ACE type is normally only meaningful in a SACL (audit/mandatory-label entries). Finding it in the DACL is unusual and worth double-checking.'
    });
  } else if (aclKind === 'sacl' && DACL_ONLY_TYPES.has(ace.type)) {
    findings.push({
      level: 'warn',
      title: `${typeInfo.name} ACE found in the SACL`,
      detail: 'This ACE type is normally only meaningful in a DACL (allow/deny entries). Finding it in the SACL is unusual and worth double-checking.'
    });
  }
  if (ace.fieldCount < 6) {
    findings.push({
      level: 'warn',
      title: 'Fewer than 6 fields in this ACE',
      detail: `Expected ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid (6 fields), found ${ace.fieldCount}. The ACE string may be truncated.`
    });
  }
  const rightsResult = decodeRights(ace.rightsRaw);
  if (!rightsResult.isHex) {
    const unrecognized = rightsResult.tokens.find(t => t.name === 'Unrecognized');
    if (unrecognized) {
      findings.push({
        level: 'warn',
        title: `Unrecognized rights token "${unrecognized.code}"`,
        detail: 'Does not match any known access-right string. It may belong to an object type this tool does not cover, or be a typo.'
      });
    }
  }
  if ((ace.type === 'A' || ace.type === 'XA' || ace.type === 'OA' || ace.type === 'ZA') && BROAD_PRINCIPALS.has(ace.sidRaw.toUpperCase())) {
    const hit = rightsResult.isHex ? [] : rightsResult.tokens.filter(t => TAKEOVER_RIGHTS.has(t.code));
    if (hit.length) {
      const sidName = SID_ALIASES[ace.sidRaw.toUpperCase()]?.name || ace.sidRaw;
      findings.push({
        level: 'danger',
        title: `${sidName} is allowed ${hit.map(h => `${h.name} (${h.code})`).join(', ')}`,
        detail: `Granting Write DAC, Write Owner or Generic All to a broad principal like ${sidName} lets any member of that group rewrite this object\u2019s permissions or take ownership of it - effectively full control.`
      });
    } else if (rightsResult.isHex) {
      findings.push({
        level: 'warn',
        title: `${ace.sidRaw} is allowed a raw access mask (${rightsResult.hex})`,
        detail: 'A broad principal is granted rights expressed as a hex access mask rather than letter codes - decode the bitmask for this object type to confirm exactly what is granted.'
      });
    }
  }
  if (ace.objectGuid) {
    const known = COMMON_OBJECT_GUIDS[ace.objectGuid.toLowerCase()];
    if (known) {
      findings.push({
        level: known.name.includes('Replication-Get-Changes-All') ? 'danger' : 'ok',
        title: `object_guid resolves to ${known.name}`,
        detail: known.description
      });
    }
  }
  return findings;
}
function analyzeDescriptor(result) {
  const findings = [];
  if (!result.hasD) {
    findings.push({
      level: 'warn',
      title: 'No D: (DACL) section in this string',
      detail: 'If this is the complete, authoritative SDDL for an object, a missing DACL token means a NULL DACL - no access check is performed and every principal has full access. If you only pasted part of a larger descriptor, this simply means the DACL was not included in what you copied.'
    });
  } else if (result.dacl.isNull) {
    findings.push({
      level: 'danger',
      title: 'DACL is explicitly NULL (NO_ACCESS_CONTROL)',
      detail: 'No access check is performed on this object at all - every principal, including anonymous ones, has full access.'
    });
  } else if (result.dacl.aces.length === 0) {
    findings.push({
      level: 'warn',
      title: 'DACL is present but empty',
      detail: 'An empty (non-null) DACL grants no access to anyone - this is effectively a deny-all, not the same as having no DACL at all.'
    });
  }
  if (result.hasS && !result.sacl.isNull && result.sacl.aces.length === 0) {
    findings.push({
      level: 'ok',
      title: 'SACL is present but empty',
      detail: 'No auditing or mandatory-label entries are defined.'
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
function renderAceCard(ace, index, aclKind) {
  const typeInfo = decodeAceType(ace.type);
  const flags = decodeAceFlags(ace.flagsRaw);
  const rights = decodeRights(ace.rightsRaw);
  const sidInfo = decodeSid(ace.sidRaw);
  const findings = analyzeAce(ace, aclKind);
  const dangerCount = findings.filter(f => f.level === 'danger').length;
  const warnCount = findings.filter(f => f.level === 'warn').length;
  const pillLabel = dangerCount ? `${dangerCount} issue${dangerCount > 1 ? 's' : ''}` : warnCount ? `${warnCount} to review` : 'routine';
  const rows = [
    attrRow('Type', ace.type || '(none)', typeInfo ? typeInfo.name : 'Unrecognized ACE type.'),
    attrRow('Flags', ace.flagsRaw || '(none)', flagsDisplay(flags)),
    attrRow('Rights', ace.rightsRaw || '(none)', rightsDisplay(rights)),
    attrRow('Object GUID', ace.objectGuid || '(none)', ace.objectGuid ? (COMMON_OBJECT_GUIDS[ace.objectGuid.toLowerCase()]?.name || 'Identifies the specific attribute/class/extended-right this ACE is scoped to.') : 'Not an object-specific ACE.'),
    attrRow('Inherit Object GUID', ace.inheritObjectGuid || '(none)', ace.inheritObjectGuid ? 'Only child objects of this class inherit the ACE.' : 'No child-class restriction on inheritance.'),
    attrRow('Account SID', ace.sidRaw || '(none)', sidDisplay(sidInfo))
  ].join('');
  const extraRow = ace.extra
    ? `<tr><th>Extra data</th><td class="mono">${escapeHtml(ace.extra)}</td><td class="small">Resource attribute / conditional-ACE expression - not parsed by this tool; shown as-is.</td></tr>`
    : '';
  return `
    <section class="card">
      <div class="row">
        <h3 style="margin:0">${aclKind === 'dacl' ? 'DACL' : 'SACL'} ACE ${index + 1}${typeInfo ? `: ${escapeHtml(typeInfo.name)}` : ''}</h3>
        <span class="spacer"></span>
        <span class="pill">${escapeHtml(pillLabel)}</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Field</th><th>Raw</th><th>Meaning</th></tr></thead>
          <tbody>${rows}${extraRow}</tbody>
        </table>
      </div>
      <p class="small mono">${escapeHtml(ace.raw)}</p>
      ${findings.length ? `<div class="sub-result">${findings.map(findingBlock).join('')}</div>` : ''}
    </section>
  `;
}
function renderAclSection(acl, kind) {
  if (!acl) return '';
  const title = kind === 'dacl' ? 'DACL (discretionary access control list)' : 'SACL (system access control list)';
  if (acl.isNull) {
    return `
      <section class="card">
        <h3>${escapeHtml(title)}</h3>
        <div class="status danger">
          <strong>NO_ACCESS_CONTROL - null ACL</strong>
          <div class="small">No access check is performed; every principal has full access.</div>
        </div>
      </section>
    `;
  }
  const flagsLine = acl.flags.length
    ? `<p class="small">Control flags: ${escapeHtml(flagsDisplay(acl.flags))}</p>`
    : '';
  if (!acl.aces.length) {
    return `
      <section class="card">
        <h3>${escapeHtml(title)}</h3>
        ${flagsLine}
        <div class="notice">Present but empty - ${kind === 'dacl' ? 'no access is granted to anyone' : 'no audit or mandatory-label entries are defined'}.</div>
      </section>
    `;
  }
  return `
    <div class="notice">${escapeHtml(title)} - ${acl.aces.length} ACE${acl.aces.length > 1 ? 's' : ''}.${acl.flags.length ? ` Control flags: ${flagsDisplay(acl.flags)}.` : ''}</div>
    ${acl.aces.map((ace, i) => renderAceCard(ace, i, kind)).join('')}
  `;
}
function renderSummary(result) {
  const descriptorFindings = analyzeDescriptor(result);
  const daclCount = result.dacl && !result.dacl.isNull ? result.dacl.aces.length : 0;
  const saclCount = result.sacl && !result.sacl.isNull ? result.sacl.aces.length : 0;
  let aceFindingDangers = 0;
  if (result.dacl && !result.dacl.isNull) {
    aceFindingDangers += result.dacl.aces.reduce((sum, ace) => sum + analyzeAce(ace, 'dacl').filter(f => f.level === 'danger').length, 0);
  }
  if (result.sacl && !result.sacl.isNull) {
    aceFindingDangers += result.sacl.aces.reduce((sum, ace) => sum + analyzeAce(ace, 'sacl').filter(f => f.level === 'danger').length, 0);
  }
  const totalDanger = aceFindingDangers + descriptorFindings.filter(f => f.level === 'danger').length;
  return `
    <section class="card">
      <h3>Summary</h3>
      <div class="grid">
        <div class="stat"><span>Owner</span><strong class="mono">${escapeHtml(result.owner ? sidDisplay(result.owner) : '(not present)')}</strong></div>
        <div class="stat"><span>Primary group</span><strong class="mono">${escapeHtml(result.group ? sidDisplay(result.group) : '(not present)')}</strong></div>
        <div class="stat"><span>DACL entries</span><strong>${result.hasD ? daclCount : '-'}</strong></div>
        <div class="stat"><span>SACL entries</span><strong>${result.hasS ? saclCount : '-'}</strong></div>
      </div>
      ${descriptorFindings.map(findingBlock).join('')}
      ${totalDanger
        ? `<div class="status danger" style="margin-top:12px"><strong>${totalDanger} issue${totalDanger > 1 ? 's' : ''} found across all ACEs</strong><div class="small">See the per-ACE breakdown below.</div></div>`
        : ''}
    </section>
  `;
}
function renderResult(result) {
  if (result.mode === 'empty') return '';
  if (result.mode === 'unrecognized') {
    return `
      <section class="card">
        <div class="status warn">
          <strong>No O:/G:/D:/S: section found</strong>
          <div class="small">Paste a full SDDL string, e.g. from <span class="mono">Get-Acl | ConvertTo-SddlString</span>, <span class="mono">icacls /save</span>, or an AD object\u2019s <span class="mono">nTSecurityDescriptor</span> in SDDL form.</div>
        </div>
      </section>
    `;
  }
  return [
    renderSummary(result),
    result.hasD ? renderAclSection(result.dacl, 'dacl') : '',
    result.hasS ? renderAclSection(result.sacl, 'sacl') : ''
  ].join('');
}
function safeExport(result) {
  if (result.mode !== 'parsed') return result;
  const expandAcl = acl => !acl ? null : {
    flagsRaw: acl.flagsRaw,
    isNull: acl.isNull,
    aces: acl.aces.map(ace => ({
      ...ace,
      typeDecoded: decodeAceType(ace.type),
      flagsDecoded: decodeAceFlags(ace.flagsRaw),
      rightsDecoded: decodeRights(ace.rightsRaw),
      sidDecoded: decodeSid(ace.sidRaw)
    }))
  };
  return {
    owner: result.owner,
    group: result.group,
    dacl: expandAcl(result.dacl),
    sacl: expandAcl(result.sacl),
    descriptorFindings: analyzeDescriptor(result)
  };
}
export function renderSddl(app) {
  app.innerHTML = `
    <div class="tool-window" id="sddlWindow">
    <div class="tool-window-header" id="sddlDragHandle" title="Drag tool">
      <span class="tool-drag-grip" aria-hidden="true">\u22ee\u22ee</span>
      <strong>SDDL decoder</strong>
    </div>
    <section class="card">
      <h2>SDDL decoder</h2>
      <p class="small">
        Paste a Security Descriptor Definition Language (SDDL) string - from  <span class="mono">Get-Acl | ConvertTo-SddlString</span>, <span class="mono">icacls /save</span>,
        <span class="mono">sc sdshow</span>, an AD object\u2019s security descriptor, or similar. Everything is
        decoded locally in your browser against the published Sddl.h constants; nothing is sent anywhere.
      </p>
      <label for="sddlInput">SDDL string</label>
      <textarea
        id="sddlInput"
        spellcheck="false"
        placeholder="O:BAG:BAD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;LCRP;;;LS)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
      ></textarea>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="sddlAnalyze">Decode</button>
        <button class="btn" id="sddlClear">Clear</button>
        <button class="btn" id="sddlCopy">Copy report</button>
        <button class="btn" id="sddlDownload">Download report</button>
      </div>
    </section>
    <div id="sddlResults"></div>
    </div>
  `;
  const input = $('#sddlInput');
  const results = $('#sddlResults');
  let lastResult = null;
  const run = () => {
    lastResult = parseSddl(input.value);
    results.innerHTML = renderResult(lastResult);
  };
  $('#sddlAnalyze').onclick = run;
  $('#sddlClear').onclick = () => {
    input.value = '';
    results.innerHTML = '';
    lastResult = null;
    input.focus();
  };
  $('#sddlCopy').onclick = async () => {
    if (!lastResult) return;
    await copyText(JSON.stringify(safeExport(lastResult), null, 2));
  };
  $('#sddlDownload').onclick = () => {
    if (!lastResult) return;
    downloadText('sddl-analysis.json', JSON.stringify(safeExport(lastResult), null, 2), 'application/json');
  };
  input.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run();
  });
  enableToolDragging(
    $('#sddlWindow'),
    $('#sddlDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
}