import { $, escapeHtml, downloadText, dropBinder, enableToolDragging } from '../utils.js';
export const metadata = {
  id: 'citrixadc',
  title: 'Citrix ADC Config Analyzer',
  description:
    'Turn a Citrix ADC / NetScaler VPX running configuration into a readable, cross-referenced report locally',
  path: '/#citrixadc'
};
const VSERVER_ATTACH = ['lb vserver', 'cs vserver', 'gslb vserver', 'vpn vserver', 'authentication vserver', 'aaa vserver'];
// Comments for my own piece of mind
const TYPE_DEFS = [
  // Virtual servers
  ['lb vserver', 'Load balancing virtual server', 'vserver', ['protocol', 'ip', 'port']],
  ['cs vserver', 'Content switching virtual server', 'vserver', ['protocol', 'ip', 'port']],
  ['gslb vserver', 'GSLB virtual server', 'vserver', ['type']],
  ['vpn vserver', 'Gateway virtual server', 'vserver', ['protocol', 'ip', 'port']],
  ['authentication vserver', 'Authentication virtual server', 'vserver', ['protocol', 'ip', 'port']],
  ['aaa vserver', 'AAA virtual server', 'vserver', ['protocol', 'ip', 'port']],
  // Backends
  ['server', 'Server', 'backend', ['address']],
  ['service', 'Service', 'backend', ['server', 'protocol', 'port']],
  ['servicegroup', 'Service group', 'backend', ['protocol']],
  ['lb monitor', 'Monitor', 'backend', ['type']],
  ['gslb service', 'GSLB service', 'backend', ['server', 'protocol', 'port']],
  ['gslb site', 'GSLB site', 'backend', ['type', 'siteIp']],
  ['lb group', 'LB group', 'backend', []],
  // SSL / TLS
  ['ssl certkey', 'Certificate', 'ssl', []],
  ['ssl profile', 'SSL profile', 'ssl', []],
  ['ssl cipher', 'Cipher group', 'ssl', []],
  ['ssl dhparam', 'DH parameter', 'ssl', []],
  ['ssl policy', 'SSL policy', 'ssl', []],
  ['ssl action', 'SSL action', 'ssl', []],
  ['ssl crl', 'Certificate revocation list', 'ssl', []],
  ['ssl ocspresponder', 'OCSP responder', 'ssl', []],
  ['ssl fipskey', 'FIPS key', 'ssl', []],
  ['ssl parameter', 'SSL global parameters', 'ssl', [], { singleton: true }],
  ['ssl global', 'SSL global bindings', 'ssl', [], { global: true }],
  ['ssl vserver', 'SSL settings', 'ssl', [], { attach: VSERVER_ATTACH }],
  ['ssl service', 'SSL settings (service)', 'ssl', [], { attach: ['service'] }],
  ['ssl servicegroup', 'SSL settings (service group)', 'ssl', [], { attach: ['servicegroup'] }],
  // Authentication, gateway, authorization
  ['authentication ldapaction', 'LDAP action', 'auth', []],
  ['authentication radiusaction', 'RADIUS action', 'auth', []],
  ['authentication tacacsaction', 'TACACS action', 'auth', []],
  ['authentication samlaction', 'SAML action', 'auth', []],
  ['authentication samlidpprofile', 'SAML IdP profile', 'auth', []],
  ['authentication samlidppolicy', 'SAML IdP policy', 'auth', []],
  ['authentication oauthaction', 'OAuth action', 'auth', []],
  ['authentication certaction', 'Client certificate action', 'auth', []],
  ['authentication webauthaction', 'Web authentication action', 'auth', []],
  ['authentication negotiateaction', 'Kerberos/NTLM action', 'auth', []],
  ['authentication epaaction', 'Endpoint analysis action', 'auth', []],
  ['authentication loginschema', 'Login schema', 'auth', []],
  ['authentication loginschemapolicy', 'Login schema policy', 'auth', []],
  ['authentication policy', 'Authentication policy', 'auth', []],
  ['authentication ldappolicy', 'LDAP policy', 'auth', []],
  ['authentication radiuspolicy', 'RADIUS policy', 'auth', []],
  ['authentication samlpolicy', 'SAML policy', 'auth', []],
  ['authentication certpolicy', 'Certificate policy', 'auth', []],
  ['authentication negotiatepolicy', 'Negotiate policy', 'auth', []],
  ['authentication policylabel', 'Authentication policy label', 'auth', []],
  ['authentication authnprofile', 'Authentication profile', 'auth', []],
  ['authorization policy', 'Authorization policy', 'auth', []],
  ['authorization action', 'Authorization action', 'auth', []],
  ['aaa parameter', 'AAA parameters', 'auth', [], { singleton: true }],
  ['aaa user', 'AAA user', 'auth', []],
  ['aaa group', 'AAA group', 'auth', []],
  ['vpn sessionaction', 'Gateway session action', 'auth', []],
  ['vpn sessionpolicy', 'Gateway session policy', 'auth', []],
  ['vpn intranetapplication', 'Intranet application', 'auth', []],
  ['vpn url', 'Bookmark URL', 'auth', []],
  ['vpn parameter', 'Gateway parameters', 'auth', [], { singleton: true }],
  ['vpn global', 'Gateway global bindings', 'auth', [], { global: true }],
  ['tm sessionaction', 'Traffic management session action', 'auth', []],
  ['tm sessionpolicy', 'Traffic management session policy', 'auth', []],
  ['tm trafficaction', 'Traffic management traffic action', 'auth', []],
  ['tm trafficpolicy', 'Traffic management traffic policy', 'auth', []],
  ['tm global', 'Traffic management global bindings', 'auth', [], { global: true }],
  // Policies and expressions
  ['cs policy', 'Content switching policy', 'policy', []],
  ['cs action', 'Content switching action', 'policy', []],
  ['cs policylabel', 'Content switching policy label', 'policy', []],
  ['rewrite policy', 'Rewrite policy', 'policy', ['rule', 'action', 'undefAction']],
  ['rewrite action', 'Rewrite action', 'policy', ['type', 'target', 'stringBuilderExpr']],
  ['rewrite policylabel', 'Rewrite policy label', 'policy', []],
  ['rewrite param', 'Rewrite parameters', 'policy', [], { singleton: true }],
  ['rewrite global', 'Rewrite global bindings', 'policy', [], { global: true }],
  ['responder policy', 'Responder policy', 'policy', ['rule', 'action', 'undefAction']],
  ['responder action', 'Responder action', 'policy', ['type', 'target']],
  ['responder policylabel', 'Responder policy label', 'policy', []],
  ['responder param', 'Responder parameters', 'policy', [], { singleton: true }],
  ['responder global', 'Responder global bindings', 'policy', [], { global: true }],
  ['cmp policy', 'Compression policy', 'policy', []],
  ['cmp action', 'Compression action', 'policy', []],
  ['cmp parameter', 'Compression parameters', 'policy', [], { singleton: true }],
  ['cmp global', 'Compression global bindings', 'policy', [], { global: true }],
  ['appflow collector', 'AppFlow collector', 'policy', []],
  ['appflow action', 'AppFlow action', 'policy', []],
  ['appflow policy', 'AppFlow policy', 'policy', []],
  ['appflow param', 'AppFlow parameters', 'policy', [], { singleton: true }],
  ['appflow global', 'AppFlow global bindings', 'policy', [], { global: true }],
  ['appfw profile', 'Web App Firewall profile', 'policy', []],
  ['appfw policy', 'Web App Firewall policy', 'policy', []],
  ['appfw settings', 'Web App Firewall settings', 'policy', [], { singleton: true }],
  ['appfw global', 'Web App Firewall global bindings', 'policy', [], { global: true }],
  ['cache policy', 'Cache policy', 'policy', []],
  ['cache contentgroup', 'Cache content group', 'policy', []],
  ['cache parameter', 'Cache parameters', 'policy', [], { singleton: true }],
  ['policy expression', 'Named expression', 'policy', ['expression']],
  ['policy patset', 'Pattern set', 'policy', []],
  ['policy dataset', 'Data set', 'policy', []],
  ['policy httpcallout', 'HTTP callout', 'policy', []],
  ['policy map', 'Policy map', 'policy', []],
  ['ns limitidentifier', 'Rate limit identifier', 'policy', []],
  ['ns variable', 'Variable', 'policy', []],
  ['ns assignment', 'Assignment', 'policy', []],
  // Network
  ['ns ip', 'IP address', 'network', ['netmask']],
  ['ns ip6', 'IPv6 address', 'network', []],
  ['vlan', 'VLAN', 'network', []],
  ['route', 'Static route', 'network', ['netmask', 'gateway'], { nameFn: routeName }],
  ['route6', 'IPv6 static route', 'network', []],
  ['interface', 'Interface', 'network', []],
  ['channel', 'Channel', 'network', []],
  ['ha node', 'HA node', 'network', ['ip']],
  ['netprofile', 'Net profile', 'network', []],
  ['network netprofile', 'Net profile', 'network', []],
  ['network bridgegroup', 'Bridge group', 'network', []],
  ['network vxlan', 'VXLAN', 'network', []],
  ['network vrid', 'VRRP virtual router', 'network', []],
  ['network rnat', 'RNAT rule', 'network', []],
  ['network l2param', 'Layer 2 parameters', 'network', [], { singleton: true }],
  ['network l3param', 'Layer 3 parameters', 'network', [], { singleton: true }],
  ['ns rnat', 'RNAT rule', 'network', []],
  ['ns acl', 'Extended ACL', 'network', []],
  ['ns acl6', 'IPv6 extended ACL', 'network', []],
  ['ns simpleacl', 'Simple ACL', 'network', []],
  ['ns trafficdomain', 'Traffic domain', 'network', []],
  ['ns tcpprofile', 'TCP profile', 'network', []],
  ['ns httpprofile', 'HTTP profile', 'network', []],
  ['ns partition', 'Admin partition', 'network', []],
  ['dns nameserver', 'DNS name server', 'network', []],
  ['dns addrec', 'DNS address record', 'network', ['address']],
  ['dns zone', 'DNS zone', 'network', []],
  ['dns view', 'DNS view', 'network', []],
  ['dns profile', 'DNS profile', 'network', []],
  ['dns parameter', 'DNS parameters', 'network', [], { singleton: true }],
  ['arp', 'ARP entry', 'network', []],
  ['lldp param', 'LLDP parameters', 'network', [], { singleton: true }],
  // System
  ['system user', 'System user', 'system', ['password'], { secretPos: ['password'] }],
  ['system group', 'System group', 'system', []],
  ['system cmdpolicy', 'Command policy', 'system', []],
  ['system parameter', 'System parameters', 'system', [], { singleton: true }],
  ['system global', 'System global bindings', 'system', [], { global: true }],
  ['snmp community', 'SNMP community', 'system', ['permissions'], { secretName: true }],
  ['snmp manager', 'SNMP manager', 'system', []],
  ['snmp trap', 'SNMP trap destination', 'system', ['type', 'destination'] ],
  ['snmp alarm', 'SNMP alarm', 'system', []],
  ['snmp user', 'SNMP user', 'system', []],
  ['snmp group', 'SNMP group', 'system', []],
  ['snmp view', 'SNMP view', 'system', []],
  ['snmp option', 'SNMP options', 'system', [], { singleton: true }],
  ['ntp server', 'NTP server', 'system', []],
  ['ntp param', 'NTP parameters', 'system', [], { singleton: true }],
  ['audit syslogaction', 'Syslog action', 'system', []],
  ['audit syslogpolicy', 'Syslog policy', 'system', []],
  ['audit syslogparams', 'Syslog parameters', 'system', [], { singleton: true }],
  ['audit nslogaction', 'NSLOG action', 'system', []],
  ['audit nslogpolicy', 'NSLOG policy', 'system', []],
  ['audit nslogparams', 'NSLOG parameters', 'system', [], { singleton: true }],
  ['audit syslog global', 'Syslog global bindings', 'system', [], { global: true }],
  ['audit nslog global', 'NSLOG global bindings', 'system', [], { global: true }],
  ['ns rpcnode', 'RPC node', 'system', [], { secretFlags: true }],
  ['cluster node', 'Cluster node', 'system', []],
  ['cluster instance', 'Cluster instance', 'system', []],
  // Singletons and toggles that live in ns.conf
  ['ns config', 'NS configuration', 'system', [], { singleton: true }],
  ['ns param', 'NS parameters', 'system', [], { singleton: true }],
  ['ns hostname', 'Host name', 'system', [], { singleton: true }],
  ['ns tcpparam', 'TCP parameters', 'system', [], { singleton: true }],
  ['ns httpparam', 'HTTP parameters', 'system', [], { singleton: true }],
  ['ns tcpbufparam', 'TCP buffer parameters', 'system', [], { singleton: true }],
  ['ns timeout', 'Timeout parameters', 'system', [], { singleton: true }],
  ['ns encryptionparams', 'Encryption parameters', 'system', [], { singleton: true }],
  ['lb parameter', 'LB parameters', 'system', [], { singleton: true }],
  ['ns feature', 'Features', 'system', [], { toggle: true }],
  ['ns mode', 'Modes', 'system', [], { toggle: true }]
];
const TYPE_MAP = new Map(
  TYPE_DEFS.map(([key, label, tab, pos, opts = {}]) => [
    key,
    { key, label, tab, pos, ...opts }
  ])
);
const KNOWN_FIRST_WORDS = new Set([
  'ns', 'lb', 'cs', 'gslb', 'ssl', 'authentication', 'authorization', 'aaa',
  'vpn', 'system', 'rewrite', 'responder', 'appflow', 'appfw', 'cache', 'cmp',
  'policy', 'network', 'dns', 'snmp', 'ha', 'audit', 'tm', 'cluster', 'ntp',
  'lldp', 'filter', 'transform', 'dos', 'videooptimization', 'stream', 'spillover',
  'botconfig', 'bot', 'contentinspection', 'ica', 'ipsec', 'lsn', 'mgmt'
]);
const VERBS = new Set([
  'add', 'set', 'bind', 'unbind', 'link', 'unlink', 'unset', 'enable', 'disable', 'rm'
]);
const TAB_INFO = [
  ['overview', 'Overview'],
  ['findings', 'Findings'],
  ['vserver', 'Virtual servers'],
  ['backend', 'Backends'],
  ['ssl', 'SSL and certificates'],
  ['auth', 'Authentication and gateway'],
  ['policy', 'Policies'],
  ['network', 'Network'],
  ['system', 'System'],
  ['unparsed', 'Unparsed']
];
const FEATURE_NAMES = {
  WL: 'Web logging', SP: 'Surge protection', LB: 'Load balancing',
  CS: 'Content switching', CR: 'Cache redirection', SC: 'SureConnect',
  CMP: 'Compression', PQ: 'Priority queuing', SSL: 'SSL offload',
  GSLB: 'Global server load balancing', HDOSP: 'HTTP DoS protection',
  CF: 'Content filtering', IC: 'Integrated caching', SSLVPN: 'Gateway (SSL VPN)',
  AAA: 'Authentication, authorization and auditing', OSPF: 'OSPF routing',
  RIP: 'RIP routing', BGP: 'BGP routing', REWRITE: 'Rewrite',
  IPV6PT: 'IPv6 protocol translation', APPFW: 'Web App Firewall',
  RESPONDER: 'Responder', HTMLINJECTION: 'HTML injection', PUSH: 'Push',
  NSBEACON: 'NS beacon', RISE: 'RISE', FIS: 'Field information system',
  APPFLOW: 'AppFlow', CH: 'Call home', ISIS: 'IS-IS routing', CLUSTER: 'Clustering'
};
const FEATURE_REQUIRED = {
  'lb vserver': 'LB',
  'cs vserver': 'CS',
  'gslb vserver': 'GSLB',
  'vpn vserver': 'SSLVPN',
  'authentication vserver': 'AAA',
  'aaa vserver': 'AAA',
  'ssl certkey': 'SSL',
  'rewrite policy': 'REWRITE',
  'responder policy': 'RESPONDER',
  'cmp policy': 'CMP',
  'appflow policy': 'APPFLOW',
  'appfw profile': 'APPFW',
  'cache policy': 'IC'
};
const SECRET_FLAGS = new Set([
  'passwd', 'password', 'passplain', 'pass', 'secret', 'radkey', 'clientsecret',
  'ldapbinddnpassword', 'bindpassword', 'tacacssecret', 'authkey', 'privpass',
  'kcdpassword', 'passphrase', 'sharedsecret', 'serversecret', 'keypassword'
]);
const HIDDEN_FLAGS = new Set([
  'devno', 'encrypted', 'encryptmethod', 'kek', 'suffix', 'digest', 'hashmethod'
]);
const DEFAULT_SNMP_COMMUNITIES = /^(public|private|community|snmp|netscaler|citrix)$/i;
const WEAK_CIPHER = /(^|[-_])(RC4|RC2|DES|3DES|DES3|EXP|EXPORT|NULL|MD5|ADH|ANON|IDEA|SEED)([-_]|$)|CBC3/i;
const FLAG_LABELS = {
  state: 'State',
  comment: 'Comment',
  lbmethod: 'Load balancing method',
  persistencetype: 'Persistence',
  timeout: 'Persistence timeout (minutes)',
  persistencebackup: 'Backup persistence',
  backuppersistencetimeout: 'Backup persistence timeout (minutes)',
  clttimeout: 'Client idle timeout (seconds)',
  svrtimeout: 'Server idle timeout (seconds)',
  maxclient: 'Maximum clients',
  maxreq: 'Maximum requests per connection',
  usip: 'Use client source IP towards server',
  useproxyport: 'Use proxy port',
  cip: 'Insert client IP header',
  cka: 'Client keep-alive',
  tcpb: 'TCP buffering',
  cmp: 'Compression',
  healthmonitor: 'Health monitoring',
  appflowlog: 'AppFlow logging',
  netprofile: 'Net profile',
  tcpprofilename: 'TCP profile',
  httpprofilename: 'HTTP profile',
  sslprofile: 'SSL profile',
  td: 'Traffic domain',
  redirecturl: 'Redirect URL',
  backupvserver: 'Backup virtual server',
  redirectportrewrite: 'Rewrite port on redirect',
  downstateflush: 'Flush connections when down',
  authentication: 'Authentication',
  authnvsname: 'Authentication virtual server',
  authn401: '401 authentication',
  icaonly: 'ICA only',
  dtls: 'DTLS',
  interval: 'Interval',
  resptimeout: 'Response timeout',
  retries: 'Retries',
  respcode: 'Expected response code',
  httprequest: 'HTTP request',
  send: 'Send string',
  recv: 'Expected reply',
  destport: 'Destination port',
  secure: 'Secure (TLS)',
  ssl3: 'SSL 3.0',
  tls1: 'TLS 1.0',
  tls11: 'TLS 1.1',
  tls12: 'TLS 1.2',
  tls13: 'TLS 1.3',
  denysslreneg: 'Deny SSL renegotiation',
  hsts: 'HSTS',
  maxage: 'HSTS max age',
  sessreuse: 'Session reuse',
  sesstimeout: 'Session timeout',
  cert: 'Certificate file',
  key: 'Key file',
  expirymonitor: 'Expiry monitor',
  notificationperiod: 'Notification period (days)',
  bundle: 'Certificate bundle',
  rule: 'Rule',
  action: 'Action',
  targetlbvserver: 'Target LB virtual server',
  serverip: 'Server IP',
  serverport: 'Server port',
  sectype: 'Transport security',
  ldapbase: 'Search base',
  ldapbinddn: 'Bind DN',
  ldaploginname: 'Login attribute',
  groupattrname: 'Group attribute',
  subattributename: 'Sub-attribute',
  ssonameattribute: 'SSO name attribute',
  authtimeout: 'Authentication timeout',
  type: 'Type',
  vserver: 'Virtual server',
  mgmtaccess: 'Management access',
  telnet: 'Telnet',
  ftp: 'FTP',
  ssh: 'SSH',
  snmp: 'SNMP',
  gui: 'GUI',
  restrictaccess: 'Restrict access',
  ifnum: 'Interfaces',
  ipaddress: 'IP address',
  netmask: 'Netmask',
  strongpassword: 'Strong passwords',
  minpasswordlen: 'Minimum password length',
  externalauth: 'External authentication',
  cmdpolicyname: 'Command policy',
  weight: 'Weight',
  priority: 'Priority',
  gotopriorityexpression: 'Next priority',
  policyname: 'Policy',
  certkeyname: 'Certificate',
  ciphername: 'Cipher',
  monitorname: 'Monitor',
  servicename: 'Service',
  domainname: 'Domain',
  sitename: 'Site',
  publicip: 'Public IP',
  gslb: 'GSLB'
};
const LB_METHOD = {
  LEASTCONNECTION: 'Least connection', ROUNDROBIN: 'Round robin',
  LEASTRESPONSETIME: 'Least response time', LEASTBANDWIDTH: 'Least bandwidth',
  LEASTPACKETS: 'Least packets', CUSTOMLOAD: 'Custom load', URLHASH: 'URL hash',
  DOMAINHASH: 'Domain hash', DESTINATIONIPHASH: 'Destination IP hash',
  SOURCEIPHASH: 'Source IP hash', SRCIPDESTIPHASH: 'Source and destination IP hash',
  SRCIPSRCPORTHASH: 'Source IP and port hash', TOKEN: 'Token',
  CALLIDHASH: 'Call ID hash', LRTM: 'Least response time (monitored)',
  STATICPROXIMITY: 'Static proximity', RTT: 'Round trip time',
  API: 'API', HASHID: 'Hash ID'
};
const PERSISTENCE = {
  SOURCEIP: 'Source IP', COOKIEINSERT: 'Cookie insert', SSLSESSION: 'SSL session ID',
  RULE: 'Rule based', URLPASSIVE: 'URL passive', CUSTOMSERVERID: 'Custom server ID',
  DESTIP: 'Destination IP', SRCIPDESTIP: 'Source and destination IP', CALLID: 'Call ID',
  RTSPSID: 'RTSP session ID', DIAMETER: 'Diameter', FIXSESSION: 'FIX session',
  NONE: 'None'
};
const FRIENDLY_VALUES = { lbmethod: LB_METHOD, persistencetype: PERSISTENCE, persistencebackup: PERSISTENCE };
const SIMPLE_VALUES = {
  ENABLED: 'Enabled', DISABLED: 'Disabled', YES: 'Yes', NO: 'No', ON: 'On', OFF: 'Off'
};
const POS_LABELS = {
  protocol: 'Protocol', ip: 'IP address', port: 'Port', address: 'Address',
  server: 'Server', type: 'Type', netmask: 'Netmask', gateway: 'Gateway',
  siteIp: 'Site IP', rule: 'Rule', action: 'Action', undefAction: 'Undefined action',
  password: 'Password', target: 'Target', expression: 'Expression',
  stringBuilderExpr: 'Value expression', permissions: 'Permissions',
  destination: 'Destination'
};
// end of weird constants
function tokenize(line) {
  const out = [];
  const n = line.length;
  let i = 0;
  while (i < n) {
    while (i < n && /\s/.test(line[i])) i++;
    if (i >= n) break;
    const start = i;
    let value = '';
    if (line[i] === '"') {
      i++;
      while (i < n) {
        const c = line[i];
        if (c === '\\' && i + 1 < n && (line[i + 1] === '"' || line[i + 1] === '\\')) {
          value += line[i + 1];
          i += 2;
          continue;
        }
        if (c === '"') {
          i++;
          break;
        }
        value += c;
        i++;
      }
      out.push({ v: value, raw: line.slice(start, i), quoted: true, secret: false });
    } else {
      while (i < n && !/\s/.test(line[i])) {
        value += line[i];
        i++;
      }
      out.push({ v: value, raw: value, quoted: false, secret: false });
    }
  }
  return out;
}
const isFlagToken = t => !t.quoted && /^-[A-Za-z][A-Za-z0-9_]*$/.test(t.v);
function maskToPrefix(mask) {
  const parts = String(mask || '').split('.');
  if (parts.length !== 4 || parts.some(p => !/^\d+$/.test(p) || Number(p) > 255)) return null;
  const bits = parts.map(p => Number(p).toString(2).padStart(8, '0')).join('');
  return /^1*0*$/.test(bits) ? bits.indexOf('0') === -1 ? 32 : bits.indexOf('0') : null;
}
function routeName(p) {
  const prefix = maskToPrefix(p[1]);
  const net = prefix === null ? `${p[0]} ${p[1] ?? ''}`.trim() : `${p[0]}/${prefix}`;
  return p[2] ? `${net} via ${p[2]}` : net;
}
function prettifyType(key) {
  return key
    .split(' ')
    .map((w, i) => (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(' ');
}
const dynamicDefs = new Map();
function defFor(typeKey) {
  if (TYPE_MAP.has(typeKey)) return TYPE_MAP.get(typeKey);
  if (!dynamicDefs.has(typeKey)) {
    dynamicDefs.set(typeKey, {
      key: typeKey,
      label: prettifyType(typeKey),
      tab: 'other',
      pos: [],
      dynamic: true
    });
  }
  return dynamicDefs.get(typeKey);
}
function parseCommand(text, line) {
  const toks = tokenize(text);
  if (!toks.length) return null;
  const verb = toks[0].v.toLowerCase();
  if (!VERBS.has(verb)) return null;
  const words = toks.slice(1).map(t => t.v.toLowerCase());
  if (!words.length) return null;
  let typeKey = null;
  let typeLen = 0;
  for (let len = Math.min(3, words.length); len >= 1; len--) {
    const candidate = words.slice(0, len).join(' ');
    if (TYPE_MAP.has(candidate)) {
      typeKey = candidate;
      typeLen = len;
      break;
    }
  }
  if (!typeKey) {
    typeLen = KNOWN_FIRST_WORDS.has(words[0]) && words.length > 1 && !words[1].startsWith('-') ? 2 : 1;
    typeKey = words.slice(0, typeLen).join(' ');
  }
  const def = defFor(typeKey);
  const rest = toks.slice(1 + typeLen);
  const positional = [];
  const flags = [];
  let current = null;
  for (const tok of rest) {
    if (isFlagToken(tok)) {
      current = { name: tok.v.slice(1), key: tok.v.slice(1).toLowerCase(), values: [], secret: false };
      flags.push(current);
    } else if (current) {
      current.values.push(tok);
    } else {
      positional.push(tok);
    }
  }
  for (const flag of flags) {
    if (SECRET_FLAGS.has(flag.key) || def.secretFlags && /pass|secret|key/i.test(flag.key)) {
      flag.secret = true;
      flag.values.forEach(t => { t.secret = true; });
    }
  }
  if (def.secretPos) {
    def.secretPos.forEach(nm => {
      const idx = def.pos.indexOf(nm) + 1;
      if (positional[idx]) positional[idx].secret = true;
    });
  }
  if (def.secretName && positional[0]) positional[0].secret = true;
  const encrypted = flags.some(f => f.key === 'encrypted');
  const hasSecret = toks.some(t => t.secret);
  return {
    line,
    text,
    verb,
    typeKey,
    def,
    toks,
    positional,
    flags,
    encrypted,
    hasSecret
  };
}
function entityKey(def, name) {
  return `${def.key}|${String(name).toLowerCase()}`;
}
function flagMap(flags) {
  const map = new Map();
  for (const f of flags) {
    map.set(f.key, { name: f.name, values: f.values, secret: f.secret });
  }
  return map;
}
function mergeFlags(target, flags) {
  for (const f of flags) {
    target.set(f.key, { name: f.name, values: f.values, secret: f.secret });
  }
}
function getEntity(model, def, name, implicit = false) {
  const key = entityKey(def, name);
  let entity = model.entities.get(key);
  if (!entity) {
    entity = {
      def,
      name,
      pos: {},
      args: [],
      flags: new Map(),
      bindings: [],
      links: [],
      ssl: null,
      cmds: [],
      line: 0,
      dup: 0,
      implicit
    };
    model.entities.set(key, entity);
  }
  return entity;
}
function findVserver(model, name) {
  for (const typeKey of VSERVER_ATTACH) {
    const entity = model.entities.get(`${typeKey}|${String(name).toLowerCase()}`);
    if (entity) return entity;
  }
  return null;
}
function attachTarget(model, def, name) {
  if (def.attach === VSERVER_ATTACH) return findVserver(model, name);
  for (const typeKey of def.attach) {
    const entity = model.entities.get(`${typeKey}|${String(name).toLowerCase()}`);
    if (entity) return entity;
  }
  return null;
}
function sslBlock(entity) {
  if (!entity.ssl) entity.ssl = { flags: new Map(), bindings: [], cmds: [] };
  return entity.ssl;
}
function applyAdd(model, cmd) {
  const { def } = cmd;
  const values = cmd.positional.map(t => t.v);
  if (def.singleton || def.toggle || def.global) {
    applySetting(model, cmd);
    return;
  }
  const name = def.nameFn ? def.nameFn(values) : values[0] ?? '(unnamed)';
  const entity = getEntity(model, def, name);
  if (entity.cmds.length && !entity.implicit) entity.dup++;
  entity.implicit = false;
  entity.line = entity.line || cmd.line;
  entity.args = values;
  def.pos.forEach((nm, i) => {
    if (cmd.positional[i + 1]) entity.pos[nm] = cmd.positional[i + 1];
  });
  mergeFlags(entity.flags, cmd.flags);
  entity.cmds.push(cmd);
}
function applySetting(model, cmd) {
  model.settings.push({
    def: cmd.def,
    verb: cmd.verb,
    args: cmd.positional,
    flags: flagMap(cmd.flags),
    cmd
  });
}
function applySet(model, cmd) {
  const { def } = cmd;
  if (def.attach) {
    const target = attachTarget(model, def, cmd.positional[0]?.v ?? '');
    if (!target) {
      model.orphans.push(cmd);
      return;
    }
    const block = sslBlock(target);
    mergeFlags(block.flags, cmd.flags);
    block.cmds.push(cmd);
    return;
  }
  if (def.singleton || def.toggle || def.global) {
    applySetting(model, cmd);
    return;
  }
  const values = cmd.positional.map(t => t.v);
  const name = def.nameFn ? def.nameFn(values) : values[0];
  if (name === undefined) {
    applySetting(model, cmd);
    return;
  }
  const entity = getEntity(model, def, name, true);
  entity.line = entity.line || cmd.line;
  mergeFlags(entity.flags, cmd.flags);
  def.pos.forEach((nm, i) => {
    if (cmd.positional[i + 1]) entity.pos[nm] = cmd.positional[i + 1];
  });
  entity.cmds.push(cmd);
}
function applyBind(model, cmd) {
  const { def } = cmd;
  const binding = {
    positional: cmd.positional.slice(def.global ? 0 : 1).map(t => t),
    flags: flagMap(cmd.flags),
    cmd
  };
  if (def.attach) {
    const target = attachTarget(model, def, cmd.positional[0]?.v ?? '');
    if (!target) {
      model.orphans.push(cmd);
      return;
    }
    const block = sslBlock(target);
    block.bindings.push(binding);
    block.cmds.push(cmd);
    return;
  }
  if (def.global) {
    const entity = getEntity(model, def, '(global)', true);
    entity.line = entity.line || cmd.line;
    entity.bindings.push(binding);
    entity.cmds.push(cmd);
    return;
  }
  const name = cmd.positional[0]?.v;
  if (name === undefined) {
    model.unparsed.push({ line: cmd.line, text: cmd.text, reason: 'Bind command without a target name' });
    return;
  }
  const entity = getEntity(model, def, name, true);
  entity.line = entity.line || cmd.line;
  entity.bindings.push(binding);
  entity.cmds.push(cmd);
}
function applyLink(model, cmd) {
  const { def } = cmd;
  const name = cmd.positional[0]?.v;
  if (name === undefined) return;
  const entity = getEntity(model, def, name, true);
  entity.links.push(...cmd.positional.slice(1).map(t => t.v));
  entity.cmds.push(cmd);
}
function applyUnset(model, cmd) {
  const { def } = cmd;
  if (def.singleton) {
    for (const s of model.settings) {
      if (s.def === def) cmd.flags.forEach(f => s.flags.delete(f.key));
    }
    return;
  }
  const name = cmd.positional[0]?.v;
  const entity = name === undefined ? null : model.entities.get(entityKey(def, name));
  if (entity) {
    cmd.flags.forEach(f => entity.flags.delete(f.key));
    entity.cmds.push(cmd);
  }
}
function applyToggle(model, cmd) {
  const names = cmd.positional.map(t => t.v.toUpperCase());
  const enabling = cmd.verb === 'enable';
  if (cmd.typeKey === 'ns feature') {
    names.forEach(n => (enabling ? model.features.add(n) : model.features.delete(n)));
    model.featuresSeen = true;
    return;
  }
  if (cmd.typeKey === 'ns mode') {
    names.forEach(n => (enabling ? model.modes.add(n) : model.modes.delete(n)));
    return;
  }
  model.toggles.push({ verb: cmd.verb, typeKey: cmd.typeKey, args: cmd.positional.map(t => t.v), line: cmd.line });
}
function applyUnbind(model, cmd) {
  const { def } = cmd;
  const name = cmd.positional[0]?.v;
  if (name === undefined) return;
  const entity = def.attach
    ? attachTarget(model, def, name)
    : model.entities.get(entityKey(def, name));
  if (!entity) return;
  const holder = def.attach ? entity.ssl : entity;
  if (!holder) return;
  const refs = cmd.positional.slice(1).map(t => t.v.toLowerCase());
  const polKey = cmd.flags.find(f => f.key === 'policyname')?.values[0]?.v.toLowerCase();
  const certKey = cmd.flags.find(f => f.key === 'certkeyname')?.values[0]?.v.toLowerCase();
  holder.bindings = holder.bindings.filter(b => {
    if (polKey && b.flags.get('policyname')?.values[0]?.v.toLowerCase() === polKey) return false;
    if (certKey && b.flags.get('certkeyname')?.values[0]?.v.toLowerCase() === certKey) return false;
    if (refs.length && b.positional[0]?.v.toLowerCase() === refs[0]) return false;
    return true;
  });
}
function parseConfig(rawText) {
  const text = String(rawText ?? '').replace(/^\uFEFF/, '');
  const lines = text.split(/\r\n|\r|\n/);
  const model = {
    lineCount: lines.length,
    commandCount: 0,
    ignored: 0,
    meta: {},
    entities: new Map(),
    settings: [],
    toggles: [],
    features: new Set(),
    featuresSeen: false,
    modes: new Set(),
    unparsed: [],
    orphans: [],
    commands: []
  };
  lines.forEach((rawLine, index) => {
    const lineNo = index + 1;
    const line = rawLine.trim();
    if (!line) return;
    if (line.startsWith('#')) {
      const ver = line.match(/^#\s*NS\s*(\d+(?:\.\d+)*)\s+Build\s+(\d+(?:\.\d+)*)/i);
      if (ver) {
        model.meta.version = ver[1];
        model.meta.build = ver[2];
      }
      const saved = line.match(/^#\s*Last modified by\s+(.+)$/i);
      if (saved) model.meta.lastModified = saved[1].trim();
      return;
    }
    if (/^(>|Done$|show\s|shell\b|Last login|Copyright|NetScaler|Citrix ADC)/i.test(line)) {
      model.ignored++;
      return;
    }
    const cmd = parseCommand(line, lineNo);
    if (!cmd) {
      model.unparsed.push({ line: lineNo, text: line, reason: 'Not a recognised configuration command' });
      return;
    }
    model.commands.push(cmd);
    model.commandCount++;
  });
  for (const cmd of model.commands) {
    if (cmd.verb === 'add') applyAdd(model, cmd);
  }
  for (const cmd of model.commands) {
    switch (cmd.verb) {
      case 'set': applySet(model, cmd); break;
      case 'bind': applyBind(model, cmd); break;
      case 'link': applyLink(model, cmd); break;
      case 'unset': applyUnset(model, cmd); break;
      case 'unbind': applyUnbind(model, cmd); break;
      case 'enable':
      case 'disable': applyToggle(model, cmd); break;
      default: break;
    }
  }
  deriveMeta(model);
  buildIndexes(model);
  return model;
}
const MASK = '••••••••';
const MASK_TEXT = '********';
const flagValues = (flags, key) => flags.get(key)?.values.map(t => t.v) ?? null;
function fv(entity, key, R = { reveal: false }) {
  const f = entity.flags.get(key);
  if (!f) return '';
  if (f.secret && !R.reveal) return MASK;
  return f.values.map(t => t.v).join(' ');
}
const hasFlag = (entity, key) => entity.flags.has(key);
const upper = v => String(v ?? '').toUpperCase();
function posVal(entity, name, R = { reveal: false }) {
  const t = entity.pos[name];
  if (!t) return '';
  return t.secret && !R.reveal ? MASK : t.v;
}
function displayName(entity, R) {
  if (entity.def.secretName && !R.reveal && !DEFAULT_SNMP_COMMUNITIES.test(entity.name)) return MASK;
  return entity.name;
}
function flagLabel(name, key) {
  return FLAG_LABELS[key] ?? name;
}
function fmtValue(key, value) {
  if (value === '') return 'set';
  const friendly = FRIENDLY_VALUES[key];
  if (friendly && friendly[upper(value)]) return friendly[upper(value)];
  if (SIMPLE_VALUES[upper(value)]) return SIMPLE_VALUES[upper(value)];
  return value;
}
const isDisabled = entity => upper(fv(entity, 'state')) === 'DISABLED';
function listener(entity) {
  const ip = entity.pos.ip?.v;
  const port = entity.pos.port?.v;
  if (!ip) return { text: '', addressable: false };
  if (ip === '0.0.0.0' && (port === '0' || port === undefined)) {
    return { text: '', addressable: false };
  }
  const host = ip.includes(':') ? `[${ip}]` : ip;
  return { text: port !== undefined ? `${host}:${port}` : host, addressable: true, ip, port };
}
function deriveMeta(model) {
  for (const s of model.settings) {
    if (s.def.key === 'ns hostname' && s.args[0]) model.meta.hostname = s.args[0].v;
    if (s.def.key === 'ns config') {
      const ip = flagValues(s.flags, 'ipaddress');
      if (ip) {
        model.meta.nsip = ip[0];
        if (ip[1]) model.meta.nsipMask = ip[1];
      }
      const nm = flagValues(s.flags, 'netmask');
      if (nm) model.meta.nsipMask = nm[0];
    }
    if (s.def.key === 'ns param') {
      const tz = flagValues(s.flags, 'timezone');
      if (tz) model.meta.timezone = tz.join(' ');
    }
  }
}
const REF_FLAGS = {
  policyname: 'policy',
  certkeyname: 'certificate',
  sslicacertkeyname: 'certificate',
  monitorname: 'monitor',
  ciphername: 'cipher',
  servicename: 'service',
  targetlbvserver: 'vserver',
  lbvserver: 'vserver',
  backupvserver: 'vserver',
  authnvsname: 'vserver',
  action: 'action',
  netprofile: 'profile',
  tcpprofilename: 'profile',
  httpprofilename: 'profile',
  sslprofile: 'profile',
  labelname: 'policylabel'
};
function buildIndexes(model) {
  model.byName = new Map();
  model.refsTo = new Map();
  const addByName = entity => {
    const key = String(entity.name).toLowerCase();
    if (!model.byName.has(key)) model.byName.set(key, []);
    model.byName.get(key).push(entity);
  };
  const addRef = (from, kind, name, extra = {}) => {
    if (!name) return;
    const key = String(name).toLowerCase();
    if (!model.refsTo.has(key)) model.refsTo.set(key, []);
    model.refsTo.get(key).push({ from, kind, name, ...extra });
  };
  for (const e of model.entities.values()) {
    addByName(e);
    if (e.def.key === 'service') addRef(e, 'server', e.pos.server?.v);
    if (e.def.key === 'gslb service') addRef(e, 'server', e.pos.server?.v);
    if (e.def.key === 'rewrite policy' || e.def.key === 'responder policy') {
      addRef(e, 'action', e.pos.action?.v);
      addRef(e, 'action', e.pos.undefAction?.v);
    }
    for (const [key, f] of e.flags) {
      const kind = REF_FLAGS[key];
      if (kind && f.values[0]) addRef(e, kind, f.values[0].v);
    }
    for (const link of e.links) addRef(e, 'certificate', link, { link: true });
    const scan = (owner, bindings) => {
      for (const b of bindings) {
        for (const [key, f] of b.flags) {
          const kind = REF_FLAGS[key];
          if (kind && f.values[0]) addRef(owner, kind, f.values[0].v, { binding: b });
        }
        if (b.positional.length && !b.flags.has('policyname') && !b.flags.has('certkeyname') &&
            !b.flags.has('ciphername') && !b.flags.has('monitorname') && !b.flags.has('servicename')) {
          const ref = b.positional[0].v;
          const defKey = owner.def.key;
          if (defKey === 'lb vserver') addRef(owner, 'service', ref, { binding: b });
          else if (defKey === 'cs vserver') addRef(owner, 'vserver', ref, { binding: b });
          else if (defKey === 'servicegroup') addRef(owner, 'server', ref, { binding: b });
        }
      }
    };
    scan(e, e.bindings);
    if (e.ssl) {
      for (const [key, f] of e.ssl.flags) {
        const kind = REF_FLAGS[key];
        if (kind && f.values[0]) addRef(e, kind, f.values[0].v);
      }
      scan(e, e.ssl.bindings);
    }
  }
}
const KIND_MATCH = {
  server: e => e.def.key === 'server',
  service: e => e.def.key === 'service' || e.def.key === 'servicegroup',
  vserver: e => VSERVER_ATTACH.includes(e.def.key),
  certificate: e => e.def.key === 'ssl certkey',
  monitor: e => e.def.key === 'lb monitor',
  policy: e => /policy$/.test(e.def.key),
  policylabel: e => /policylabel$/.test(e.def.key),
  action: e => /(action|policy)$/.test(e.def.key),
  profile: e => /profile$/.test(e.def.key),
  cipher: e => e.def.key === 'ssl cipher'
};
function resolve(model, kind, name) {
  const list = model.byName.get(String(name).toLowerCase()) ?? [];
  const match = KIND_MATCH[kind];
  return match ? list.find(match) ?? null : list[0] ?? null;
}
function usedBy(model, entity, kinds) {
  const list = model.refsTo.get(String(entity.name).toLowerCase()) ?? [];
  const out = [];
  const seen = new Set();
  for (const r of list) {
    if (kinds && !kinds.includes(r.kind)) continue;
    if (r.from === entity) continue;
    const label = `${r.from.def.label} ${r.from.name}`;
    if (!seen.has(label)) {
      seen.add(label);
      out.push(r.from);
    }
  }
  return out;
}
function isBuiltinName(name) {
  return /^(ns[_-]|tcp-default|ping-default|http|https|tcp|ping|arp|nd6|dns|ftp|udp-ecv|tcp-ecv|http-ecv|tcps|tcps-ecv|https-ecv|ldap|radius|mysql|mssql|oracle|smtp|pop3|imap|snmp|xdm|xnc|rtsp|sip-udp|diameter|sasl|ldap-ecv|ldns-ping|ldns-tcp|ldns-dns|dynamicvserver|default|nsrpc|nsdefault)/i.test(name);
}
function entitiesOf(model, key) {
  return [...model.entities.values()].filter(e => e.def.key === key);
}
function vservers(model) {
  return [...model.entities.values()].filter(e => VSERVER_ATTACH.includes(e.def.key));
}
function serverAddress(model, serverName) {
  const s = resolve(model, 'server', serverName);
  if (s) return s.pos.address?.v || serverName;
  return /^[\d.:a-f]+$/i.test(serverName) ? serverName : '';
}
function membersOf(model, backend, R) {
  if (backend.def.key === 'servicegroup') {
    return backend.bindings
      .filter(b => b.positional.length && !b.flags.has('monitorname'))
      .map(b => {
        const server = b.positional[0].v;
        const port = b.positional[1]?.v ?? '';
        const address = serverAddress(model, server);
        return {
          server,
          address,
          port,
          weight: fv({ flags: b.flags }, 'weight', R),
          state: upper(fv({ flags: b.flags }, 'state', R)),
          resolved: !!resolve(model, 'server', server) || !!address
        };
      });
  }
  if (backend.def.key === 'service') {
    const server = backend.pos.server?.v ?? '';
    return [{
      server,
      address: serverAddress(model, server),
      port: backend.pos.port?.v ?? '',
      weight: '',
      state: upper(fv(backend, 'state', R)),
      resolved: !!resolve(model, 'server', server) || /^[\d.:a-f]+$/i.test(server)
    }];
  }
  return [];
}
function memberText(m) {
  const who = m.address && m.address !== m.server ? `${m.server} (${m.address})` : m.server;
  const parts = [m.port ? `${who}:${m.port}` : who];
  if (m.weight) parts.push(`weight ${m.weight}`);
  if (m.state === 'DISABLED') parts.push('disabled');
  if (!m.resolved) parts.push('server not defined');
  return parts.join(', ');
}
function analyze(model) {
  const F = [];
  const R = { reveal: true };
  const add = (sev, title, detail, ref = '', line = 0) => F.push({ sev, title, detail, ref, line });
  const aggregate = (sev, title, detail, names, ref = '') => {
    if (!names.length) return;
    const shown = names.slice(0, 12).join(', ');
    const more = names.length > 12 ? ` and ${names.length - 12} more` : '';
    add(sev, title, `${detail} ${shown}${more}.`, ref);
  };
  const ents = [...model.entities.values()];
  const totalObjects = ents.length + model.settings.length;
  for (const e of entitiesOf(model, 'ns ip')) {
    const type = upper(fv(e, 'type')) || 'SNIP';
    if (upper(fv(e, 'telnet')) === 'ENABLED') {
      add('high', 'Telnet enabled', 'Telnet sends credentials in clear text. Disable it and use SSH.', `IP ${e.name}`, e.line);
    }
    if (upper(fv(e, 'ftp')) === 'ENABLED') {
      add('high', 'FTP enabled', 'FTP sends credentials in clear text. Disable it and use SFTP or SCP.', `IP ${e.name}`, e.line);
    }
    if (upper(fv(e, 'gui')) === 'ENABLED') {
      add('warn', 'Management GUI allows plain HTTP', 'The GUI is set to ENABLED rather than SECUREONLY, so HTTP management is allowed.', `IP ${e.name}`, e.line);
    }
    if (type === 'SNIP' && upper(fv(e, 'mgmtaccess')) === 'ENABLED') {
      add('warn', 'Management access on a subnet IP', 'Management access is enabled on a SNIP. Restrict it to the NSIP or a dedicated management network.', `IP ${e.name}`, e.line);
    }
  }
  for (const e of entitiesOf(model, 'snmp community')) {
    if (DEFAULT_SNMP_COMMUNITIES.test(e.name)) {
      add('high', 'Default SNMP community string', `The community "${e.name}" is a well-known default. Replace it with a unique value or move to SNMPv3.`, `SNMP community ${e.name}`, e.line);
    }
  }
  const sysParams = model.settings.filter(s => s.def.key === 'system parameter');
  const strong = sysParams.some(s => upper(flagValues(s.flags, 'strongpassword')?.[0]) === 'ENABLED');
  const strongOff = sysParams.find(s => upper(flagValues(s.flags, 'strongpassword')?.[0]) === 'DISABLED');
  if (strongOff) {
    add('warn', 'Strong passwords disabled', 'Password complexity is explicitly turned off for local system users.', 'System parameters', strongOff.cmd.line);
  } else if (!strong && entitiesOf(model, 'system user').length && totalObjects > 20) {
    add('info', 'Strong passwords not enforced', 'No -strongpassword ENABLED setting was found for local system users.', 'System parameters');
  }
  const plain = model.commands.filter(c => c.hasSecret && !c.encrypted);
  if (plain.length) {
    const lines = plain.slice(0, 15).map(c => c.line).join(', ');
    add('warn', 'Secret values not marked as encrypted',
      `${plain.length} command(s) contain a password or key without the -encrypted flag, so the value may be stored in clear text. Lines: ${lines}${plain.length > 15 ? ', …' : ''}.`);
  }
  const dups = ents.filter(e => e.dup > 0).map(e => `${e.def.label} ${e.name}`);
  aggregate('warn', 'Objects defined more than once', 'The same object name was added multiple times:', dups);
  const vs = vservers(model);
  const listeners = new Map();
  for (const e of vs) {
    const proto = upper(e.pos.protocol?.v);
    const l = listener(e);
    const disabled = isDisabled(e);
    const ref = `${e.def.label} ${e.name}`;
    if (disabled) add('info', 'Virtual server is disabled', 'The virtual server is administratively disabled and will not accept traffic.', ref, e.line);
    if (l.addressable && l.port !== '0' && l.port !== undefined) {
      const key = `${l.ip}|${l.port}|${proto}|${upper(fv(e, 'td')) || '0'}`;
      if (!listeners.has(key)) listeners.set(key, []);
      listeners.get(key).push(e);
    }
    if (['SSL', 'SSL_TCP', 'DTLS'].includes(proto)) {
      const hasCert = e.ssl?.bindings.some(b => b.flags.has('certkeyname'));
      if (!hasCert) {
        add('high', 'SSL virtual server without a certificate', 'No certificate is bound to this SSL virtual server, so it cannot complete a TLS handshake.', ref, e.line);
      }
    }
    if (['vpn vserver', 'authentication vserver', 'aaa vserver'].includes(e.def.key) && proto && !['SSL', 'SSL_TCP'].includes(proto) && l.addressable) {
      add('warn', 'Sign-in endpoint not using TLS', `The virtual server uses protocol ${proto}. Credentials would cross the network unencrypted.`, ref, e.line);
    }
    if (e.def.key === 'vpn vserver' && upper(fv(e, 'authentication')) === 'OFF') {
      add('warn', 'Gateway without authentication', 'Authentication is switched off on this Gateway virtual server.', ref, e.line);
    }
    if (e.ssl) {
      if (upper(fv({ flags: e.ssl.flags }, 'ssl3')) === 'ENABLED') add('high', 'SSL 3.0 enabled', 'SSL 3.0 is broken (POODLE). Disable it.', ref);
      if (upper(fv({ flags: e.ssl.flags }, 'tls1')) === 'ENABLED') add('warn', 'TLS 1.0 enabled', 'TLS 1.0 is deprecated. Disable it unless a legacy client requires it.', ref);
      if (upper(fv({ flags: e.ssl.flags }, 'tls11')) === 'ENABLED') add('warn', 'TLS 1.1 enabled', 'TLS 1.1 is deprecated. Disable it unless a legacy client requires it.', ref);
    }
    if (e.def.key === 'lb vserver') {
      const targets = e.bindings.filter(b => b.positional.length && !b.flags.has('policyname'));
      if (!targets.length && !hasFlag(e, 'redirecturl') && !hasFlag(e, 'backupvserver') && !disabled) {
        add('warn', 'No backend bound', 'No service or service group is bound, so this virtual server will be DOWN.', ref, e.line);
      }
      if (!l.addressable) {
        const reached = usedBy(model, e, ['vserver']).length > 0;
        if (!reached) add('info', 'Non-addressable virtual server is not referenced', 'It has no listening address and no content switching virtual server targets it, so nothing can reach it.', ref, e.line);
      }
    }
    if (e.def.key === 'cs vserver') {
      for (const b of e.bindings) {
        const target = b.flags.get('targetlbvserver')?.values[0]?.v ?? (!b.flags.has('policyname') ? b.positional[0]?.v : null);
        if (target && !resolve(model, 'vserver', target)) {
          add('warn', 'Content switching target not found', `Target virtual server "${target}" is not defined in this configuration.`, ref, e.line);
        }
      }
    }
  }
  for (const list of listeners.values()) {
    if (list.length > 1) {
      const l = listener(list[0]);
      add('warn', 'Two virtual servers share one address and port', `${list.map(x => x.name).join(' and ')} both listen on ${l.text} with the same protocol.`, list[0].def.label);
    }
  }
  const unresolvedServers = new Set();
  for (const b of [...entitiesOf(model, 'service'), ...entitiesOf(model, 'servicegroup')]) {
    for (const m of membersOf(model, b, R)) {
      if (!m.resolved) unresolvedServers.add(`${m.server} (in ${b.name})`);
    }
    if (upper(fv(b, 'healthmonitor')) === 'NO') {
      add('warn', 'Health monitoring is off', 'The backend is never checked, so traffic can still be sent to a failed server.', `${b.def.label} ${b.name}`, b.line);
    }
    for (const mb of b.bindings) {
      const mon = mb.flags.get('monitorname')?.values[0]?.v;
      if (mon && !resolve(model, 'monitor', mon) && !isBuiltinName(mon)) {
        add('info', 'Monitor not defined here', `Monitor "${mon}" is not defined in this configuration. It may be a built-in monitor.`, `${b.def.label} ${b.name}`);
      }
    }
  }
  aggregate('warn', 'References to undefined servers', 'These backend members point to a server that is not defined:', [...unresolvedServers]);
  const unusedServers = entitiesOf(model, 'server')
    .filter(s => !usedBy(model, s, ['server']).length).map(s => s.name);
  aggregate('info', 'Servers not used by any service', 'These servers are defined but never referenced:', unusedServers);
  const unboundBackends = [...entitiesOf(model, 'service'), ...entitiesOf(model, 'servicegroup')]
    .filter(b => !usedBy(model, b, ['service']).length).map(b => b.name);
  aggregate('info', 'Backends not bound to any virtual server', 'These services or service groups are not bound anywhere:', unboundBackends);
  // Certificates
  const certs = entitiesOf(model, 'ssl certkey');
  for (const c of certs) {
    if (upper(fv(c, 'expirymonitor')) === 'DISABLED') {
      add('warn', 'Certificate expiry monitoring is off', 'The appliance will not warn before this certificate expires.', `Certificate ${c.name}`, c.line);
    }
  }
  const unusedCerts = certs
    .filter(c => !/^ns-/i.test(c.name) && !usedBy(model, c, ['certificate']).length)
    .map(c => c.name);
  aggregate('info', 'Certificates not bound anywhere', 'These certificates are installed but not bound or linked:', unusedCerts);
  const missingCerts = new Set();
  for (const [key, refs] of model.refsTo) {
    for (const r of refs) {
      if (r.kind === 'certificate' && !r.link && !resolve(model, 'certificate', r.name) && !/^ns-/i.test(r.name)) {
        missingCerts.add(`${r.name} (from ${r.from.name})`);
      }
    }
    void key;
  }
  aggregate('warn', 'Bound certificates that are not defined', 'These certificate names are bound but not defined here:', [...missingCerts]);
  for (const p of entitiesOf(model, 'ssl profile')) {
    const ref = `SSL profile ${p.name}`;
    if (upper(fv(p, 'ssl3')) === 'ENABLED') add('high', 'SSL 3.0 enabled', 'SSL 3.0 is broken (POODLE). Disable it.', ref, p.line);
    if (upper(fv(p, 'tls1')) === 'ENABLED') add('warn', 'TLS 1.0 enabled', 'TLS 1.0 is deprecated. Disable it unless a legacy client requires it.', ref, p.line);
    if (upper(fv(p, 'tls11')) === 'ENABLED') add('warn', 'TLS 1.1 enabled', 'TLS 1.1 is deprecated. Disable it unless a legacy client requires it.', ref, p.line);
  }
  // Ciphers
  const weak = new Set();
  const scanCiphers = (owner, bindings) => {
    for (const b of bindings) {
      const name = b.flags.get('ciphername')?.values[0]?.v;
      if (!name) continue;
      if (upper(name) === 'ALL') weak.add(`ALL (in ${owner.name})`);
      else if (WEAK_CIPHER.test(name)) weak.add(`${name} (in ${owner.name})`);
    }
  };
  for (const e of ents) {
    scanCiphers(e, e.bindings);
    if (e.ssl) scanCiphers(e, e.ssl.bindings);
  }
  aggregate('warn', 'Weak or overly broad ciphers bound', 'Review these cipher bindings:', [...weak]);
  for (const a of entitiesOf(model, 'authentication ldapaction')) {
    const sec = upper(fv(a, 'sectype'));
    if (!sec || sec === 'PLAINTEXT') {
      add('warn', 'LDAP action without TLS', 'The LDAP action uses clear text. Use -secType SSL or TLS so bind credentials are protected.', `LDAP action ${a.name}`, a.line);
    }
  }
  const unusedPolicies = ents
    .filter(e => /^(rewrite|responder|cs|cmp|authentication|appflow|appfw|cache) (policy|ldappolicy|radiuspolicy|samlpolicy)$/.test(e.def.key) || e.def.key === 'authentication policy')
    .filter(e => !usedBy(model, e, ['policy']).length)
    .map(e => `${e.name}`);
  aggregate('info', 'Policies not bound anywhere', 'These policies are defined but never bound:', unusedPolicies);
  if (model.featuresSeen) {
    const missing = new Map();
    for (const e of ents) {
      const need = FEATURE_REQUIRED[e.def.key];
      if (need && !model.features.has(need) && !e.implicit) {
        if (!missing.has(need)) missing.set(need, new Set());
        missing.get(need).add(e.def.label);
      }
    }
    for (const [feature, types] of missing) {
      add('warn', `Feature ${feature} is not enabled`, `${[...types].join(', ')} configured, but "enable ns feature" does not include ${feature}.`);
    }
  }
  if (totalObjects > 20) {
    const notes = [];
    if (!entitiesOf(model, 'ntp server').length) notes.push('NTP servers');
    if (!entitiesOf(model, 'audit syslogaction').length && !entitiesOf(model, 'audit nslogaction').length) notes.push('remote logging (syslog)');
    if (!entitiesOf(model, 'dns nameserver').length) notes.push('DNS name servers');
    if (notes.length) add('info', 'Common operational settings not found', `No ${notes.join(', ')} found in this configuration.`);
    if (!entitiesOf(model, 'ha node').length) {
      add('info', 'No HA node configured', 'No "add ha node" was found. This is normal for a standalone appliance.');
    }
    const hasIps = entitiesOf(model, 'ns ip').length > 0;
    const hasDefault = entitiesOf(model, 'route').some(r => r.args[0] === '0.0.0.0' && r.args[1] === '0.0.0.0');
    if (hasIps && !hasDefault) add('info', 'No default route', 'No route to 0.0.0.0/0 was found. Traffic to other networks needs a route or policy-based route.');
  }
  if (model.orphans.length) {
    add('info', 'SSL settings for unknown objects', `${model.orphans.length} "set/bind ssl" command(s) refer to objects that are not in this paste, for example on line ${model.orphans[0].line}.`);
  }
  const order = { high: 0, warn: 1, info: 2 };
  F.sort((a, b) => order[a.sev] - order[b.sev]);
  return F;
}
function settingsRows(entity, R, skip = []) {
  const rows = [];
  for (const [key, f] of entity.flags) {
    if (HIDDEN_FLAGS.has(key) || skip.includes(key)) continue;
    const value = f.secret && !R.reveal ? MASK : f.values.map(t => t.v).join(' ');
    rows.push([flagLabel(f.name, key), fmtValue(key, value)]);
  }
  return rows;
}
function positionalRows(entity, R, skip = []) {
  const rows = [];
  for (const nm of entity.def.pos) {
    if (skip.includes(nm)) continue;
    const v = posVal(entity, nm, R);
    if (v !== '') rows.push([POS_LABELS[nm] ?? nm, v]);
  }
  return rows;
}
function cmdText(cmd, R) {
  return cmd.toks.map(t => (t.secret && !R.reveal ? MASK_TEXT : t.raw)).join(' ');
}
function protocolSummary(flags, profile) {
  const chosen = [];
  const map = [['ssl3', 'SSL 3.0'], ['tls1', 'TLS 1.0'], ['tls11', 'TLS 1.1'], ['tls12', 'TLS 1.2'], ['tls13', 'TLS 1.3']];
  for (const [key, label] of map) {
    const own = upper(flagValues(flags, key)?.[0]);
    const inherited = profile ? upper(fv(profile, key)) : '';
    const value = own || inherited;
    if (value === 'ENABLED') chosen.push(label);
  }
  return chosen;
}
function policyBindings(model, owner) {
  const rows = [];
  const scan = bindings => {
    for (const b of bindings) {
      const name = b.flags.get('policyname')?.values[0]?.v;
      if (!name) continue;
      const pol = resolve(model, 'policy', name);
      const rule = pol ? (fv(pol, 'rule') || pol.pos.rule?.v || '') : '';
      const action = pol ? (fv(pol, 'action') || pol.pos.action?.v || '') : '';
      rows.push({
        name,
        kind: pol ? pol.def.label : 'Not defined here',
        priority: b.flags.get('priority')?.values[0]?.v ?? '',
        next: b.flags.get('gotopriorityexpression')?.values.map(t => t.v).join(' ') ?? '',
        type: b.flags.get('type')?.values[0]?.v ?? '',
        target: b.flags.get('targetlbvserver')?.values[0]?.v ?? b.flags.get('lbvserver')?.values[0]?.v ?? '',
        rule,
        action
      });
    }
  };
  scan(owner.bindings);
  rows.sort((a, b) => (Number(a.priority) || 1e9) - (Number(b.priority) || 1e9));
  return rows;
}
function vserverVM(model, e, R) {
  const l = listener(e);
  const protocol = e.pos.protocol?.v ?? e.pos.type?.v ?? '';
  const disabled = isDisabled(e);
  const ssl = e.ssl;
  const profileName = ssl ? flagValues(ssl.flags, 'sslprofile')?.[0] : fv(e, 'sslprofile');
  const profile = profileName ? resolve(model, 'profile', profileName) : null;
  // Backends
  const backends = [];
  if (e.def.key === 'lb vserver') {
    for (const b of e.bindings) {
      if (!b.positional.length || b.flags.has('policyname')) continue;
      const ref = b.positional[0].v;
      const target = resolve(model, 'service', ref);
      const members = target ? membersOf(model, target, R) : [];
      backends.push({
        ref,
        kind: target ? target.def.label : 'Not defined here',
        weight: b.flags.get('weight')?.values[0]?.v ?? '',
        members: members.map(memberText),
        healthMonitors: target ? target.bindings
          .map(x => x.flags.get('monitorname')?.values[0]?.v).filter(Boolean) : []
      });
    }
  }
  if (e.def.key === 'cs vserver') {
    for (const b of e.bindings) {
      if (b.flags.has('policyname')) continue;
      const ref = b.positional[0]?.v;
      if (ref) {
        const target = resolve(model, 'vserver', ref);
        backends.push({ ref, kind: target ? `${target.def.label} (default target)` : 'Not defined here', weight: '', members: [], healthMonitors: [] });
      }
    }
  }
  if (e.def.key === 'gslb vserver') {
    for (const b of e.bindings) {
      const svc = b.flags.get('servicename')?.values[0]?.v;
      if (svc) {
        const t = resolve(model, 'service', svc);
        backends.push({ ref: svc, kind: 'GSLB service', weight: b.flags.get('weight')?.values[0]?.v ?? '', members: t ? [`${t.pos.server?.v ?? ''}:${t.pos.port?.v ?? ''}`] : [], healthMonitors: [] });
      }
    }
  }
  const domains = e.bindings
    .filter(b => b.flags.has('domainname'))
    .map(b => b.flags.get('domainname').values[0].v);
  const policies = policyBindings(model, e);
  // Certificates and SSL
  const certs = ssl
    ? ssl.bindings.filter(b => b.flags.has('certkeyname')).map(b => {
        const name = b.flags.get('certkeyname').values[0].v;
        const extra = [];
        if (b.flags.has('sniCert') || b.flags.has('snicert')) extra.push('SNI');
        if (b.flags.has('ca')) extra.push('CA');
        return { name, extra: extra.join(', '), defined: !!resolve(model, 'certificate', name) };
      })
    : [];
  const ciphers = ssl
    ? ssl.bindings.filter(b => b.flags.has('ciphername')).map(b => b.flags.get('ciphername').values[0].v)
    : [];
  const protocols = ssl ? protocolSummary(ssl.flags, profile) : [];
  const sslSettings = ssl
    ? settingsRows({ flags: ssl.flags }, R, ['ssl3', 'tls1', 'tls11', 'tls12', 'tls13'])
    : [];
  const other = [];
  for (const b of e.bindings) {
    if (b.flags.has('policyname') || b.flags.has('servicename') || b.flags.has('domainname')) continue;
    if (b.positional.length && (e.def.key === 'lb vserver' || e.def.key === 'cs vserver')) continue;
    const txt = [
      ...b.positional.map(t => (t.secret && !R.reveal ? MASK : t.v)),
      ...[...b.flags.values()].map(f => `-${f.name}${f.values.length ? ' ' + f.values.map(t => (f.secret && !R.reveal ? MASK : t.v)).join(' ') : ''}`)
    ].join(' ');
    if (txt) other.push(txt);
  }
  const settings = settingsRows(e, R, ['state', 'comment', 'sslprofile']);
  const comment = fv(e, 'comment', R);
  const parts = [];
  const proto = protocol ? ` using ${protocol}` : '';
  if (e.def.key === 'gslb vserver') {
    parts.push(`${e.def.label} "${e.name}" (type ${protocol || 'unknown'}) answers DNS queries for ${domains.length ? domains.join(', ') : 'its bound domains'}.`);
  } else if (l.addressable) {
    parts.push(`${e.def.label} "${e.name}" listens on ${l.text}${proto}.`);
  } else {
    parts.push(`${e.def.label} "${e.name}"${proto} has no address of its own${e.def.key === 'lb vserver' ? '. It is reached through a content switching virtual server.' : '.'}`);
  }
  if (disabled) parts.push('It is disabled.');
  if (e.def.key === 'lb vserver') {
    const method = fmtValue('lbmethod', fv(e, 'lbmethod') || 'LEASTCONNECTION');
    const persist = fv(e, 'persistencetype');
    parts.push(`Load balancing method: ${method}${fv(e, 'lbmethod') ? '' : ' (default)'}.`);
    if (persist && upper(persist) !== 'NONE') {
      const t = fv(e, 'timeout');
      parts.push(`Persistence: ${fmtValue('persistencetype', persist)}${t ? `, ${t} minutes` : ''}.`);
    }
    const total = backends.reduce((n, b) => n + b.members.length, 0);
    if (backends.length) {
      parts.push(`Traffic is sent to ${backends.map(b => b.ref).join(', ')} (${total} member${total === 1 ? '' : 's'}).`);
    } else if (fv(e, 'redirecturl')) {
      parts.push(`It redirects clients to ${fv(e, 'redirecturl')}.`);
    } else {
      parts.push('No backend is bound.');
    }
  }
  if (e.def.key === 'cs vserver') {
    const targets = new Set(policies.map(p => p.target).filter(Boolean));
    parts.push(`${policies.length} policy binding${policies.length === 1 ? '' : 's'} route${policies.length === 1 ? 's' : ''} requests${targets.size ? ` to ${[...targets].join(', ')}` : ''}.`);
    if (backends.length) parts.push(`Default target: ${backends[0].ref}.`);
  }
  if (e.def.key === 'vpn vserver' || e.def.key === 'authentication vserver' || e.def.key === 'aaa vserver') {
    const auth = fv(e, 'authnvsname');
    if (auth) parts.push(`Sign-in is handled by authentication virtual server ${auth}.`);
    if (upper(fv(e, 'authentication')) === 'OFF') parts.push('Authentication is off.');
  }
  if (certs.length) parts.push(`Certificate${certs.length > 1 ? 's' : ''}: ${certs.map(c => c.name).join(', ')}.`);
  if (protocols.length) parts.push(`TLS versions enabled: ${protocols.join(', ')}.`);
  else if (ssl) parts.push(profile ? `TLS versions come from SSL profile ${profile.name}.` : 'TLS versions use the appliance defaults.');
  return {
    name: e.name,
    typeLabel: e.def.label,
    typeKey: e.def.key,
    state: disabled ? 'Disabled' : 'Enabled',
    listener: l.text,
    protocol,
    summary: parts.join(' '),
    comment,
    settings,
    backends,
    policies,
    certs,
    ciphers,
    protocols,
    sslProfile: profile ? profile.name : profileName || '',
    sslSettings,
    other,
    commands: [...e.cmds, ...(e.ssl ? e.ssl.cmds : [])].map(c => cmdText(c, R)),
    search: [
      e.name, e.def.label, l.text, protocol, ...settings.flat(),
      ...backends.map(b => b.ref), ...backends.flatMap(b => b.members),
      ...policies.map(p => p.name), ...certs.map(c => c.name)
    ].join(' ').toLowerCase()
  };
}
function catalogueVM(model, e, R) {
  const rows = [...positionalRows(e, R), ...settingsRows(e, R)];
  const extra = [];
  if (e.def.key === 'servicegroup' || e.def.key === 'service') {
    const members = membersOf(model, e, R).map(memberText);
    if (members.length) extra.push(['Members', members]);
    const monitors = e.bindings.map(b => b.flags.get('monitorname')?.values[0]?.v).filter(Boolean);
    if (monitors.length) extra.push(['Monitors', monitors]);
  }
  if (e.def.key === 'ssl cipher') {
    const list = e.bindings
      .filter(b => b.flags.has('ciphername'))
      .map(b => {
        const pr = b.flags.get('cipherpriority')?.values[0]?.v;
        return `${b.flags.get('ciphername').values[0].v}${pr ? ` (priority ${pr})` : ''}`;
      });
    if (list.length) extra.push(['Ciphers', list]);
  }
  if (e.def.key === 'ssl profile') {
    const ciphers = e.bindings.filter(b => b.flags.has('ciphername')).map(b => b.flags.get('ciphername').values[0].v);
    if (ciphers.length) extra.push(['Ciphers', ciphers]);
  }
  if (e.def.key === 'ssl certkey' && e.links.length) {
    extra.push(['Linked to CA', e.links]);
  }
  if (e.def.key === 'vlan') {
    const ifs = e.bindings.map(b => {
      const ifn = b.flags.get('ifnum')?.values.map(t => t.v).join(' ');
      if (!ifn) return null;
      return b.flags.has('tagged') ? `${ifn} (tagged)` : ifn;
    }).filter(Boolean);
    if (ifs.length) extra.push(['Interfaces', ifs]);
    const ips = e.bindings.map(b => b.flags.get('ipaddress')?.values.join(' ')).filter(Boolean)
      .concat(e.bindings.map(b => { const f = b.flags.get('ipaddress'); return f ? f.values.map(t => t.v).join(' ') : null; }).filter(Boolean));
    void ips;
    const ipList = e.bindings.map(b => b.flags.get('ipaddress')?.values.map(t => t.v).join(' ')).filter(Boolean);
    if (ipList.length) extra.push(['IP addresses', ipList]);
  }
  if (e.def.key === 'system user') {
    const groups = e.bindings.map(b => b.positional[0]?.v
      ? `${b.positional[0].v}${b.positional[1] ? ` (priority ${b.positional[1].v})` : ''}` : b.flags.get('cmdpolicyname')?.values[0]?.v)
      .filter(Boolean);
    if (groups.length) extra.push(['Command policies', groups]);
  }
  const bindingLines = [];
  if (!['servicegroup', 'service', 'ssl cipher', 'ssl profile', 'vlan', 'system user'].includes(e.def.key)) {
    for (const b of e.bindings) {
      const txt = [
        ...b.positional.map(t => (t.secret && !R.reveal ? MASK : t.v)),
        ...[...b.flags.values()].map(f => `-${f.name}${f.values.length ? ' ' + f.values.map(t => (f.secret && !R.reveal ? MASK : t.v)).join(' ') : ''}`)
      ].join(' ');
      if (txt) bindingLines.push(txt);
    }
    if (bindingLines.length) extra.push(['Bindings', bindingLines]);
  }
  const used = usedBy(model, e, null).map(u => `${u.def.label} ${u.name}`);
  return {
    name: displayName(e, R),
    typeLabel: e.def.label,
    typeKey: e.def.key,
    implicit: e.implicit,
    rows,
    extra,
    usedBy: used,
    commands: e.cmds.map(c => cmdText(c, R)),
    search: [e.name, e.def.label, ...rows.flat(), ...extra.flatMap(x => x[1]), ...used].join(' ').toLowerCase()
  };
}
function settingsVM(model, R) {
  return model.settings.map(s => {
    const rows = [];
    s.args.forEach(t => rows.push(['Value', t.secret && !R.reveal ? MASK : t.v]));
    for (const [key, f] of s.flags) {
      if (HIDDEN_FLAGS.has(key)) continue;
      const v = f.secret && !R.reveal ? MASK : f.values.map(t => t.v).join(' ');
      rows.push([flagLabel(f.name, key), fmtValue(key, v)]);
    }
    return { label: s.def.label, tab: s.def.tab, key: s.def.key, rows, verb: s.verb };
  }).filter(s => s.rows.length);
}
const h = escapeHtml;
function kvTable(rows) {
  if (!rows.length) return '';
  return `<div class="table-wrap"><table class="cx-kv"><tbody>${rows.map(([k, v]) =>
    `<tr><th scope="row">${h(k)}</th><td>${h(v)}</td></tr>`).join('')}</tbody></table></div>`;
}
function listHtml(items) {
  if (!items.length) return '';
  return `<ul class="cx-list">${items.map(i => `<li>${h(i)}</li>`).join('')}</ul>`;
}
function collapsible(title, inner, open = false) {
  return `<details class="cx-sub"${open ? ' open' : ''}><summary>${h(title)}</summary>${inner}</details>`;
}
function commandsBlock(cmds) {
  if (!cmds.length) return '';
  return collapsible(`Configuration commands (${cmds.length})`, `<pre class="cx-raw">${h(cmds.join('\n'))}</pre>`);
}
function stateChip(state) {
  return `<span class="cx-state ${state === 'Enabled' ? 'on' : 'off'}">${h(state)}</span>`;
}
function renderVserver(vm) {
  const policyTable = vm.policies.length
    ? `<h4>Policies</h4><div class="table-wrap"><table><thead><tr>
        <th>Priority</th><th>Policy</th><th>Kind</th><th>Bind point</th><th>Rule</th><th>Action or target</th><th>Next</th>
      </tr></thead><tbody>${vm.policies.map(p => `<tr>
        <td>${h(p.priority || '-')}</td><td>${h(p.name)}</td><td>${h(p.kind)}</td>
        <td>${h(p.type || '-')}</td><td class="mono">${h(p.rule || '-')}</td>
        <td class="mono">${h(p.target || p.action || '-')}</td><td>${h(p.next || '-')}</td>
      </tr>`).join('')}</tbody></table></div>`
    : '';
  const backendTable = vm.backends.length
    ? `<h4>Bound backends</h4><div class="table-wrap"><table><thead><tr>
        <th>Name</th><th>Kind</th><th>Members</th><th>Monitors</th></tr></thead><tbody>${vm.backends.map(b => `<tr>
        <td>${h(b.ref)}${b.weight ? `<br><span class="small">weight ${h(b.weight)}</span>` : ''}</td>
        <td>${h(b.kind)}</td>
        <td>${b.members.length ? listHtml(b.members) : '<span class="small">none</span>'}</td>
        <td>${b.healthMonitors.length ? h(b.healthMonitors.join(', ')) : '<span class="small">default</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`
    : '';
  const sslRows = [];
  if (vm.certs.length) sslRows.push(['Certificates', vm.certs.map(c => `${c.name}${c.extra ? ` (${c.extra})` : ''}${c.defined ? '' : ' - not defined here'}`).join(', ')]);
  if (vm.sslProfile) sslRows.push(['SSL profile', vm.sslProfile]);
  if (vm.protocols.length) sslRows.push(['TLS versions enabled', vm.protocols.join(', ')]);
  if (vm.ciphers.length) sslRows.push(['Ciphers', vm.ciphers.join(', ')]);
  vm.sslSettings.forEach(r => sslRows.push(r));
  const sslBlockHtml = sslRows.length ? `<h4>SSL</h4>${kvTable(sslRows)}` : '';
  return `
    <details class="cx-item" data-search="${h(vm.search)}">
      <summary>
        <strong>${h(vm.name)}</strong>
        <span class="pill">${h(vm.typeLabel)}</span>
        ${vm.listener ? `<span class="mono">${h(vm.listener)}</span>` : '<span class="small">no listener</span>'}
        ${vm.protocol ? `<span class="small">${h(vm.protocol)}</span>` : ''}
        ${stateChip(vm.state)}
      </summary>
      <div class="cx-item-body">
        <p class="cx-plain">${h(vm.summary)}</p>
        ${vm.comment ? `<p class="small">Comment: ${h(vm.comment)}</p>` : ''}
        ${backendTable}
        ${policyTable}
        ${sslBlockHtml}
        ${vm.settings.length ? `<h4>Settings</h4>${kvTable(vm.settings)}` : ''}
        ${vm.other.length ? `<h4>Other bindings</h4>${listHtml(vm.other)}` : ''}
        ${commandsBlock(vm.commands)}
      </div>
    </details>`;
}
function renderCatalogueTable(vms) {
  return `<div class="table-wrap"><table class="cx-cat"><thead><tr>
      <th>Name</th><th>Details</th><th>Used by</th></tr></thead><tbody>${vms.map(vm => `
      <tr data-search="${h(vm.search)}">
        <td><strong>${h(vm.name)}</strong>${vm.implicit ? '<br><span class="small">changed by set/bind only</span>' : ''}</td>
        <td>
          ${kvTable(vm.rows)}
          ${vm.extra.map(([label, items]) => `<p class="cx-label">${h(label)}</p>${listHtml(items)}`).join('')}
          ${commandsBlock(vm.commands)}
        </td>
        <td>${vm.usedBy.length ? listHtml(vm.usedBy) : '<span class="small">-</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`;
}
function groupBy(list, fn) {
  const map = new Map();
  for (const item of list) {
    const key = fn(item);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(item);
  }
  return map;
}
function renderSettingsBlock(settings) {
  if (!settings.length) return '';
  return settings.map(s => `
    <div data-search="${h((s.label + ' ' + s.rows.flat().join(' ')).toLowerCase())}">
      <h4>${h(s.label)}</h4>${kvTable(s.rows)}
    </div>`).join('');
}
function panelFor(model, tab, R, cache) {
  if (tab === 'vserver') {
    const vms = cache.vservers;
    if (!vms.length) return '<p class="small">No virtual servers found in this configuration.</p>';
    const groups = groupBy(vms, vm => vm.typeLabel);
    return [...groups].map(([label, list]) =>
      `<h3>${h(label)}s (${list.length})</h3>${list.map(renderVserver).join('')}`).join('');
  }
  const entities = cache.catalogue.filter(vm => tabOf(vm) === tab);
  const settings = cache.settings.filter(s => s.tab === tab);
  if (!entities.length && !settings.length) {
    return '<p class="small">Nothing in this section was found in the configuration.</p>';
  }
  const groups = groupBy(entities, vm => vm.typeLabel);
  const tables = [...groups].map(([label, list]) =>
    `<h3>${h(label)} (${list.length})</h3>${renderCatalogueTable(list)}`).join('');
  const settingsHtml = settings.length ? `<h3>Global settings</h3>${renderSettingsBlock(settings)}` : '';
  return tables + settingsHtml;
}
const tabOf = vm => vm._tab;
function renderFindings(findings) {
  if (!findings.length) {
    return '<div class="status ok">The local checks found nothing to review. This does not prove the configuration is secure.</div>';
  }
  return `<div class="table-wrap"><table class="cx-findings"><thead><tr>
      <th>Severity</th><th>Finding</th><th>Object</th><th>Details</th></tr></thead><tbody>${findings.map(f => `
      <tr data-search="${h((f.title + ' ' + f.detail + ' ' + f.ref).toLowerCase())}">
        <td><span class="cx-sev ${f.sev}">${f.sev === 'high' ? 'High' : f.sev === 'warn' ? 'Review' : 'Info'}</span></td>
        <td><strong>${h(f.title)}</strong>${f.line ? `<br><span class="small">line ${f.line}</span>` : ''}</td>
        <td>${h(f.ref || '-')}</td>
        <td>${h(f.detail)}</td>
      </tr>`).join('')}</tbody></table></div>`;
}
function renderOverview(model, findings, cache) {
  const count = key => entitiesOf(model, key).length;
  const policyCount = [...model.entities.values()].filter(e => /policy$/.test(e.def.key)).length;
  const high = findings.filter(f => f.sev === 'high').length;
  const review = findings.filter(f => f.sev === 'warn').length;
  const ips = entitiesOf(model, 'ns ip');
  const snips = ips.filter(e => (upper(fv(e, 'type')) || 'SNIP') === 'SNIP').length;
  const vips = ips.filter(e => upper(fv(e, 'type')) === 'VIP').length;
  const stat = (label, value) => `<div class="stat"><span>${h(label)}</span><strong>${h(value)}</strong></div>`;
  const features = [...model.features].map(f => FEATURE_NAMES[f] ? `${f} (${FEATURE_NAMES[f]})` : f);
  const facts = [];
  if (model.meta.hostname) facts.push(['Host name', model.meta.hostname]);
  if (model.meta.version) facts.push(['Firmware', `${model.meta.version} build ${model.meta.build}`]);
  if (model.meta.lastModified) facts.push(['Last modified', model.meta.lastModified]);
  if (model.meta.nsip) facts.push(['Management IP (NSIP)', `${model.meta.nsip}${model.meta.nsipMask ? ' / ' + model.meta.nsipMask : ''}`]);
  if (model.meta.timezone) facts.push(['Time zone', model.meta.timezone]);
  if (features.length) facts.push(['Enabled features', features.join(', ')]);
  if (model.modes.size) facts.push(['Enabled modes', [...model.modes].join(', ')]);
  const ntp = entitiesOf(model, 'ntp server').map(e => e.name);
  if (ntp.length) facts.push(['NTP servers', ntp.join(', ')]);
  const dns = entitiesOf(model, 'dns nameserver').map(e => e.name);
  if (dns.length) facts.push(['DNS name servers', dns.join(', ')]);
  const ha = entitiesOf(model, 'ha node').map(e => `${e.name}${e.pos.ip ? ' (' + e.pos.ip.v + ')' : ''}`);
  if (ha.length) facts.push(['HA nodes', ha.join(', ')]);
  const topFindings = findings.filter(f => f.sev !== 'info').slice(0, 5);
  return `
    <div class="grid cx-stats">
      ${stat('Load balancing virtual servers', count('lb vserver'))}
      ${stat('Content switching virtual servers', count('cs vserver'))}
      ${stat('Gateway virtual servers', count('vpn vserver'))}
      ${stat('GSLB virtual servers', count('gslb vserver'))}
      ${stat('Services and service groups', count('service') + count('servicegroup'))}
      ${stat('Servers', count('server'))}
      ${stat('Certificates', count('ssl certkey'))}
      ${stat('Policies', policyCount)}
      ${stat('Virtual IPs / subnet IPs', `${vips} / ${snips}`)}
      ${stat('VLANs', count('vlan'))}
      ${stat('Static routes', count('route'))}
      ${stat('High / review findings', `${high} / ${review}`)}
    </div>
    ${facts.length ? `<h3>Appliance</h3>${kvTable(facts)}` : ''}
    ${topFindings.length ? `<h3>Most important findings</h3>${renderFindings(topFindings)}<p class="small">See the Findings tab for the full list.</p>` : ''}
    <p class="small cx-note">
      Read from ${model.lineCount.toLocaleString()} lines and ${model.commandCount.toLocaleString()} commands.
      Findings are heuristics based only on the pasted text. Built-in objects, licensing, cluster state and runtime
      status are not part of a running configuration.
    </p>`;
}
function renderUnparsed(model) {
  const dyn = cacheOther(model);
  const parts = [];
  if (model.unparsed.length) {
    parts.push(`<h3>Lines that were not recognised (${model.unparsed.length})</h3>
      <div class="table-wrap"><table><thead><tr><th>Line</th><th>Text</th><th>Reason</th></tr></thead><tbody>
      ${model.unparsed.map(u => `<tr data-search="${h(u.text.toLowerCase())}"><td>${u.line}</td><td class="mono">${h(u.text)}</td><td>${h(u.reason)}</td></tr>`).join('')}
      </tbody></table></div>`);
  }
  if (model.orphans.length) {
    parts.push(`<h3>SSL commands for objects that are not in the paste (${model.orphans.length})</h3>
      <pre class="cx-raw">${h(model.orphans.map(c => c.text).join('\n'))}</pre>`);
  }
  if (model.toggles.length) {
    parts.push(`<h3>Other enable / disable commands (${model.toggles.length})</h3>
      ${listHtml(model.toggles.map(t => `${t.verb} ${t.typeKey} ${t.args.join(' ')}`.trim()))}`);
  }
  if (dyn) parts.push(dyn);
  if (model.ignored) parts.push(`<p class="small">${model.ignored} console line(s) such as prompts were skipped.</p>`);
  return parts.length ? parts.join('') : '<p class="small">Every line was recognised.</p>';
}
let otherCache = null;
function cacheOther(model) {
  const html = otherCache ? otherCache(model) : '';
  return html;
}
function md(s) {
  return String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}
function toMarkdown(model, findings, cache, R) {
  const out = [];
  out.push('# Citrix ADC configuration report');
  out.push('');
  out.push(`Generated locally in the browser on ${new Date().toISOString()}.`);
  out.push(`Source: ${model.lineCount} lines, ${model.commandCount} commands.` +
    (R.reveal ? ' Secret values are included.' : ' Secret values are masked.'));
  out.push('');
  const facts = [];
  if (model.meta.hostname) facts.push(`- Host name: ${model.meta.hostname}`);
  if (model.meta.version) facts.push(`- Firmware: ${model.meta.version} build ${model.meta.build}`);
  if (model.meta.nsip) facts.push(`- Management IP (NSIP): ${model.meta.nsip}`);
  if (model.features.size) facts.push(`- Enabled features: ${[...model.features].join(', ')}`);
  if (model.modes.size) facts.push(`- Enabled modes: ${[...model.modes].join(', ')}`);
  if (facts.length) {
    out.push('## Appliance', '', ...facts, '');
  }
  out.push('## Findings', '');
  if (!findings.length) out.push('No findings.', '');
  else {
    for (const f of findings) {
      const sev = f.sev === 'high' ? 'High' : f.sev === 'warn' ? 'Review' : 'Info';
      out.push(`- **${sev}: ${f.title}**${f.ref ? ` (${f.ref})` : ''}${f.line ? ` line ${f.line}` : ''}. ${f.detail}`);
    }
    out.push('');
  }
  out.push('## Virtual servers', '');
  if (!cache.vservers.length) out.push('None found.', '');
  for (const vm of cache.vservers) {
    out.push(`### ${vm.name} (${vm.typeLabel})`, '');
    out.push(vm.summary, '');
    const facts2 = [];
    if (vm.listener) facts2.push(`- Listener: ${vm.listener}${vm.protocol ? ' ' + vm.protocol : ''}`);
    facts2.push(`- State: ${vm.state}`);
    if (vm.comment) facts2.push(`- Comment: ${vm.comment}`);
    out.push(...facts2, '');
    if (vm.backends.length) {
      out.push('Backends:', '');
      for (const b of vm.backends) {
        out.push(`- ${b.ref} (${b.kind})${b.weight ? `, weight ${b.weight}` : ''}`);
        b.members.forEach(m => out.push(`  - ${m}`));
      }
      out.push('');
    }
    if (vm.policies.length) {
      out.push('Policies:', '', '| Priority | Policy | Kind | Bind point | Rule | Action or target |', '| --- | --- | --- | --- | --- | --- |');
      vm.policies.forEach(p => out.push(`| ${md(p.priority)} | ${md(p.name)} | ${md(p.kind)} | ${md(p.type)} | ${md(p.rule)} | ${md(p.target || p.action)} |`));
      out.push('');
    }
    const ssl = [];
    if (vm.certs.length) ssl.push(`- Certificates: ${vm.certs.map(c => c.name).join(', ')}`);
    if (vm.sslProfile) ssl.push(`- SSL profile: ${vm.sslProfile}`);
    if (vm.protocols.length) ssl.push(`- TLS versions enabled: ${vm.protocols.join(', ')}`);
    if (vm.ciphers.length) ssl.push(`- Ciphers: ${vm.ciphers.join(', ')}`);
    if (ssl.length) out.push('SSL:', '', ...ssl, '');
    if (vm.settings.length) {
      out.push('Settings:', '', '| Setting | Value |', '| --- | --- |');
      vm.settings.forEach(([k, v]) => out.push(`| ${md(k)} | ${md(v)} |`));
      out.push('');
    }
  }
  const sections = [
    ['backend', 'Backends'],
    ['ssl', 'SSL and certificates'],
    ['auth', 'Authentication and gateway'],
    ['policy', 'Policies'],
    ['network', 'Network'],
    ['system', 'System'],
    ['other', 'Other objects']
  ];
  for (const [tab, title] of sections) {
    const list = cache.catalogue.filter(vm => vm._tab === tab);
    const sets = cache.settings.filter(s => s.tab === tab);
    if (!list.length && !sets.length) continue;
    out.push(`## ${title}`, '');
    const groups = groupBy(list, vm => vm.typeLabel);
    for (const [label, items] of groups) {
      out.push(`### ${label} (${items.length})`, '');
      for (const vm of items) {
        out.push(`- **${vm.name}**`);
        vm.rows.forEach(([k, v]) => out.push(`  - ${k}: ${v}`));
        vm.extra.forEach(([k, arr]) => out.push(`  - ${k}: ${arr.join('; ')}`));
        if (vm.usedBy.length) out.push(`  - Used by: ${vm.usedBy.join('; ')}`);
      }
      out.push('');
    }
    if (sets.length) {
      out.push('### Global settings', '');
      for (const s of sets) {
        out.push(`- **${s.label}**`);
        s.rows.forEach(([k, v]) => out.push(`  - ${k}: ${v}`));
      }
      out.push('');
    }
  }
  if (model.unparsed.length) {
    out.push('## Lines that were not recognised', '');
    model.unparsed.forEach(u => out.push(`- line ${u.line}: \`${u.text.replace(/`/g, "'")}\``));
    out.push('');
  }
  return out.join('\n');
}
function toJson(model, findings, R) {
  const bindingObj = b => ({
    args: b.positional.map(t => (t.secret && !R.reveal ? MASK_TEXT : t.v)),
    flags: Object.fromEntries([...b.flags.values()].map(f => [
      f.name,
      f.values.map(t => (f.secret && !R.reveal ? MASK_TEXT : t.v)).join(' ')
    ]))
  });
  return {
    note: 'Local-only Citrix ADC configuration analysis. No data left this browser.',
    generatedAt: new Date().toISOString(),
    secretsIncluded: !!R.reveal,
    source: { lines: model.lineCount, commands: model.commandCount },
    appliance: { ...model.meta, features: [...model.features], modes: [...model.modes] },
    findings,
    settings: settingsVM(model, R).map(s => ({
      type: s.label,
      values: Object.fromEntries(s.rows.map(([k, v]) => [k, v]))
    })),
    objects: [...model.entities.values()].map(e => ({
      type: e.def.key,
      name: e.def.secretName && !R.reveal && !DEFAULT_SNMP_COMMUNITIES.test(e.name) ? MASK_TEXT : e.name,
      line: e.line || undefined,
      positional: Object.fromEntries(Object.entries(e.pos).map(([k, t]) => [k, t.secret && !R.reveal ? MASK_TEXT : t.v])),
      flags: Object.fromEntries([...e.flags.values()]
        .filter(f => !HIDDEN_FLAGS.has(f.name.toLowerCase()))
        .map(f => [f.name, f.values.map(t => (f.secret && !R.reveal ? MASK_TEXT : t.v)).join(' ')])),
      bindings: e.bindings.map(bindingObj),
      ssl: e.ssl ? {
        flags: Object.fromEntries([...e.ssl.flags.values()].map(f => [f.name, f.values.map(t => t.v).join(' ')])),
        bindings: e.ssl.bindings.map(bindingObj)
      } : undefined,
      links: e.links.length ? e.links : undefined
    })),
    unparsed: model.unparsed
  };
}
function buildCache(model, R) {
  const vservers = vserversVM(model, R);
  const catalogue = [...model.entities.values()]
    .filter(e => !VSERVER_ATTACH.includes(e.def.key) && !e.def.attach)
    .map(e => {
      const vm = catalogueVM(model, e, R);
      vm._tab = e.def.tab;
      return vm;
    });
  const settings = settingsVM(model, R);
  return { vservers, catalogue, settings };
}
function vserversVM(model, R) {
  return vservers(model).map(e => vserverVM(model, e, R));
}
function countsFor(model, cache, findings) {
  const by = tab => cache.catalogue.filter(vm => vm._tab === tab).length +
    cache.settings.filter(s => s.tab === tab).length;
  return {
    findings: findings.length,
    vserver: cache.vservers.length,
    backend: by('backend'),
    ssl: by('ssl'),
    auth: by('auth'),
    policy: by('policy'),
    network: by('network'),
    system: by('system'),
    unparsed: model.unparsed.length + model.orphans.length + cache.catalogue.filter(v => v._tab === 'other').length
  };
}
function renderOther(cache) {
  const list = cache.catalogue.filter(vm => vm._tab === 'other');
  if (!list.length) return '';
  const groups = groupBy(list, vm => vm.typeLabel);
  return `<h3>Objects of types this tool does not know yet (${list.length})</h3>
    <p class="small">These were still read as objects with their parameters, but they are not interpreted further.</p>` +
    [...groups].map(([label, items]) => `<h4>${h(label)} (${items.length})</h4>${renderCatalogueTable(items)}`).join('');
}
// End of weird functions
export function renderCitrixAdc(app) {
  app.innerHTML = `
    <div class="tool-window" id="cxWindow">
      <div class="tool-window-header" id="cxDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>Citrix ADC config analyzer</strong>
      </div>
      <section class="card">
        <h2>Citrix ADC / NetScaler VPX running configuration</h2>
        <p class="small">
          Paste the output of <code>show ns runningConfig</code> or the contents of <code>ns.conf</code>. The tool turns the command list into virtual servers, backends, certificates, policies and network settings, resolves the references between them and points out things to review. Everything is parsed in this browser tab. Nothing is uploaded.
        </p>
        <div class="dropzone" id="cxDrop">
          Drop an <code>ns.conf</code>, .conf, .txt or .log file here or <button class="btn" type="button" id="cxPick">Select file</button>
          <input hidden id="cxFile" type="file" accept=".conf,.cfg,.txt,.log,.ns">
        </div>
        <label for="cxInput" class="cx-input-label">Configuration text</label>
        <textarea id="cxInput" spellcheck="false" rows="16"
          placeholder="add server web01 10.10.1.11&#10;add serviceGroup sg_web HTTP&#10;bind serviceGroup sg_web web01 80&#10;add lb vserver vs_web SSL 10.10.20.10 443 -lbMethod LEASTCONNECTION&#10;bind lb vserver vs_web sg_web"></textarea>
        <div class="row cx-toolbar">
          <button class="btn primary" type="button" id="cxAnalyze">Parse configuration</button>
          <button class="btn" type="button" id="cxExample">Load example</button>
          <button class="btn" type="button" id="cxClear">Clear</button>
          <span class="spacer"></span>
          <label class="checkline cx-reveal">
            <input type="checkbox" id="cxReveal">
            Show secret values
          </label>
        </div>
        <p class="small" id="cxInfo" role="status"></p>
      </section>
      <section class="card" id="cxResultCard" hidden>
        <div class="row cx-toolbar">
          <input id="cxFilter" type="search" class="cx-filter"
            placeholder="Filter by name, IP address, policy, certificate…"
            aria-label="Filter results">
          <span class="spacer"></span>
          <button class="btn" type="button" id="cxExportMd">Download readable report (.md)</button>
          <button class="btn" type="button" id="cxExportJson">Download JSON</button>
        </div>
        <p class="small" id="cxSecretNote"></p>
        <div id="cxResult"></div>
      </section>
    </div>`;
  enableToolDragging(
    $('#cxWindow'),
    $('#cxDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
  let state = null;
  let activeTab = 'overview';
  const info = $('#cxInfo');
  const setInfo = text => { info.textContent = text; };
  const reveal = () => $('#cxReveal').checked;
  function tabsHtml(counts) {
    return `<div class="cx-tabs" role="tablist" aria-label="Result sections">${TAB_INFO.map(([id, label]) => {
      const c = counts[id];
      const badge = c !== undefined ? ` <span class="cx-count">${c}</span>` : '';
      return `<button type="button" class="cx-tab" role="tab" id="cxTab-${id}" data-tab="${id}"
        aria-selected="${id === activeTab}" aria-controls="cxPanel-${id}" tabindex="${id === activeTab ? 0 : -1}">${h(label)}${badge}</button>`;
    }).join('')}</div>`;
  }
  function render() {
    if (!state) return;
    const R = { reveal: reveal() };
    const cache = buildCache(state.model, R);
    state.cache = cache;
    state.R = R;
    const counts = countsFor(state.model, cache, state.findings);
    const panels = {
      overview: renderOverview(state.model, state.findings, cache),
      findings: renderFindings(state.findings),
      unparsed: renderUnparsed(state.model) + renderOther(cache)
    };
    for (const [id] of TAB_INFO) {
      if (!panels[id]) panels[id] = panelFor(state.model, id, R, cache);
    }
    $('#cxResult').innerHTML = tabsHtml(counts) + TAB_INFO.map(([id]) =>
      `<div class="cx-panel" role="tabpanel" id="cxPanel-${id}" aria-labelledby="cxTab-${id}"${id === activeTab ? '' : ' hidden'}>${panels[id]}</div>`
    ).join('');
    $('#cxSecretNote').textContent = R.reveal
      ? 'Secret values are visible on screen and will be included in downloads.'
      : 'Passwords, keys and community strings are masked on screen and in downloads.';
    applyFilter();
  }
  function selectTab(id, focus = false) {
    activeTab = id;
    document.querySelectorAll('#cxResult .cx-tab').forEach(btn => {
      const on = btn.dataset.tab === id;
      btn.setAttribute('aria-selected', String(on));
      btn.tabIndex = on ? 0 : -1;
      if (on && focus) btn.focus();
    });
    document.querySelectorAll('#cxResult .cx-panel').forEach(panel => {
      panel.hidden = panel.id !== `cxPanel-${id}`;
    });
  }
  function applyFilter() {
    const q = $('#cxFilter').value.trim().toLowerCase();
    document.querySelectorAll('#cxResult [data-search]').forEach(el => {
      el.hidden = q !== '' && !el.dataset.search.includes(q);
    });
  }
  $('#cxResult').addEventListener('click', event => {
    const btn = event.target.closest('.cx-tab');
    if (btn) selectTab(btn.dataset.tab);
  });
  $('#cxResult').addEventListener('keydown', event => {
    const btn = event.target.closest('.cx-tab');
    if (!btn || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const ids = TAB_INFO.map(t => t[0]);
    let i = ids.indexOf(btn.dataset.tab);
    if (event.key === 'ArrowRight') i = (i + 1) % ids.length;
    if (event.key === 'ArrowLeft') i = (i - 1 + ids.length) % ids.length;
    if (event.key === 'Home') i = 0;
    if (event.key === 'End') i = ids.length - 1;
    event.preventDefault();
    selectTab(ids[i], true);
  });
  $('#cxFilter').addEventListener('input', applyFilter);
  $('#cxReveal').addEventListener('change', render);
  function analyzeText() {
    const text = $('#cxInput').value;
    if (!text.trim()) {
      setInfo('Paste a running configuration first, or load the example.');
      $('#cxResultCard').hidden = true;
      return;
    }
    try {
      const model = parseConfig(text);
      if (!model.commandCount) {
        setInfo('No Citrix ADC commands were found. A running configuration contains lines such as "add lb vserver …" or "bind serviceGroup …".');
        $('#cxResultCard').hidden = true;
        state = null;
        return;
      }
      const findings = analyze(model);
      state = { model, findings };
      activeTab = 'overview';
      $('#cxResultCard').hidden = false;
      render();
      setInfo(`Parsed ${model.commandCount.toLocaleString()} commands into ${model.entities.size.toLocaleString()} objects. ${findings.filter(f => f.sev !== 'info').length} item(s) need review.`);
    } catch (error) {
      state = null;
      $('#cxResultCard').hidden = true;
      setInfo(`The configuration could not be parsed: ${error?.message || 'unknown error'}.`);
    }
  }
  async function loadFile(file) {
    try {
      const buf = await file.arrayBuffer();
      let text;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
      } catch {
        text = new TextDecoder('windows-1252').decode(buf);
      }
      $('#cxInput').value = text;
      setInfo(`Loaded ${file.name} locally (${text.length.toLocaleString()} characters).`);
      analyzeText();
    } catch (error) {
      setInfo(`The file could not be read: ${error?.message || 'unknown error'}.`);
    }
  }
  $('#cxPick').addEventListener('click', () => $('#cxFile').click());
  $('#cxFile').addEventListener('change', () => {
    const file = $('#cxFile').files[0];
    if (file) loadFile(file);
  });
  dropBinder($('#cxDrop'), files => files[0] && loadFile(files[0]));
  $('#cxAnalyze').addEventListener('click', analyzeText);
  $('#cxInput').addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') analyzeText();
  });
  $('#cxExample').addEventListener('click', () => {
    $('#cxInput').value = EXAMPLE_CONFIG;
    setInfo('Example configuration loaded. All names, addresses and secrets are made up.');
    analyzeText();
  });
  $('#cxClear').addEventListener('click', () => {
    $('#cxInput').value = '';
    $('#cxFile').value = '';
    $('#cxFilter').value = '';
    $('#cxResult').innerHTML = '';
    $('#cxResultCard').hidden = true;
    state = null;
    setInfo('');
  });
  $('#cxExportMd').addEventListener('click', () => {
    if (!state) return;
    downloadText(
      'citrix-adc-config-report.md',
      toMarkdown(state.model, state.findings, state.cache, state.R),
      'text/markdown;charset=utf-8'
    );
  });
  $('#cxExportJson').addEventListener('click', () => {
    if (!state) return;
    downloadText(
      'citrix-adc-config-analysis.json',
      JSON.stringify(toJson(state.model, state.findings, state.R), null, 2),
      'application/json;charset=utf-8'
    );
  });
}
export const _internals = { parseConfig, analyze, buildCache, toMarkdown, toJson, tokenize };
const EXAMPLE_CONFIG = String.raw`#NS13.1 Build 53.17
# Last modified by ` + "`save config`" + String.raw`, Mon Sep 28 08:12:41 2026
set ns config -IPAddress 10.10.0.10 -netmask 255.255.255.0
set ns hostname adc-vpx-01
set ns param -timezone "GMT+01:00-CET-Europe/Vienna"
enable ns feature WL SP LB CS CMP SSL AAA REWRITE RESPONDER SSLVPN
enable ns mode FR L3 Edge USNIP PMTUD
set system parameter -strongpassword ENABLED -minpasswordlen 12
add system user svc_monitor "9f1c2b7a0d5e4c3b8a6f1e2d3c4b5a69" -encrypted -encryptmethod ENCMTHD_3 -timeout 900
bind system user svc_monitor read-only 100
add ns ip 10.10.0.11 255.255.255.0 -vServer DISABLED -telnet ENABLED -ftp ENABLED -gui ENABLED -mgmtAccess ENABLED
add ns ip 10.10.20.10 255.255.255.0 -type VIP
add ns ip 10.10.20.11 255.255.255.0 -type VIP
add vlan 20
bind vlan 20 -ifnum 1/1 -tagged
bind vlan 20 -IPAddress 10.10.20.5 255.255.255.0
add route 0.0.0.0 0.0.0.0 10.10.0.1
add dns nameServer 10.10.0.53
add ntp server 10.10.0.123 -minpoll 6 -maxpoll 10
add snmp community public ALL
add ssl certKey wildcard_example_2026 -cert wildcard_example_2026.pem -key wildcard_example_2026.key -expiryMonitor ENABLED -notificationPeriod 30
add ssl certKey legacy_portal -cert legacy_portal.pem -key legacy_portal.key -expiryMonitor DISABLED
add ssl certKey unused_test -cert unused_test.pem -key unused_test.key
add ssl profile prof_frontend_legacy -tls1 ENABLED -tls11 ENABLED -tls12 ENABLED -tls13 ENABLED
add ssl cipher grp_modern
bind ssl cipher grp_modern -cipherName TLS1.3-AES256-GCM-SHA384 -cipherPriority 1
bind ssl cipher grp_modern -cipherName TLS1.2-ECDHE-RSA-AES256-GCM-SHA384 -cipherPriority 2
add server web01 10.10.1.11
add server web02 10.10.1.12
add server web03 web03.corp.example.com
add server legacy01 10.10.1.50
add server unused01 10.10.1.99
add lb monitor mon_health HTTP -respCode 200 -httpRequest "GET /health" -interval 5 -resptimeout 2 -secure YES
add serviceGroup sg_web SSL -maxClient 0 -maxReq 0 -cip ENABLED X-Forwarded-For -usip NO -useproxyport YES -cltTimeout 180 -svrTimeout 360 -CKA YES -TCPB NO -CMP NO
add serviceGroup sg_portal HTTP -healthMonitor NO -cip ENABLED X-Forwarded-For
add serviceGroup sg_orphan HTTP
add service svc_legacy legacy01 HTTP 8080 -gslb NONE -maxClient 0
bind serviceGroup sg_web web01 443 -weight 1
bind serviceGroup sg_web web02 443 -weight 1
bind serviceGroup sg_web web03 443 -weight 2 -state DISABLED
bind serviceGroup sg_web -monitorName mon_health
bind serviceGroup sg_portal ghost01 8080
add rewrite action rw_act_hsts insert_http_header Strict-Transport-Security "\"max-age=31536000; includeSubDomains\""
add rewrite policy rw_pol_hsts true rw_act_hsts
add rewrite policy rw_pol_unused true rw_act_hsts
add responder action rsp_act_maint respondwith "\"HTTP/1.1 503 Service Unavailable\r\n\r\n\""
add responder policy rsp_pol_maint "HTTP.REQ.URL.CONTAINS(\"/maintenance\")" rsp_act_maint
add lb vserver vs_web SSL 10.10.20.10 443 -persistenceType COOKIEINSERT -timeout 30 -lbMethod LEASTCONNECTION -cltTimeout 180 -comment "Public web front end"
add lb vserver vs_portal SSL 10.10.20.11 443 -persistenceType SOURCEIP -timeout 20 -sslProfile prof_frontend_legacy
add lb vserver vs_portal_dup SSL 10.10.20.11 443
add lb vserver vs_legacy HTTP 0.0.0.0 0 -state DISABLED
add lb vserver vs_web_redirect HTTP 10.10.20.10 80 -redirectURL "https://www.example.com" -persistenceType NONE
add lb vserver vs_api HTTP 0.0.0.0 0 -lbMethod ROUNDROBIN
add lb vserver vs_empty SSL 10.10.20.12 443
bind lb vserver vs_web sg_web
bind lb vserver vs_web -policyName rw_pol_hsts -priority 100 -gotoPriorityExpression END -type RESPONSE
bind lb vserver vs_web -policyName rsp_pol_maint -priority 90 -gotoPriorityExpression END -type REQUEST
bind lb vserver vs_portal sg_portal
bind lb vserver vs_legacy svc_legacy
bind lb vserver vs_api sg_web
set ssl vserver vs_web -tls11 DISABLED -tls1 DISABLED -sessReuse ENABLED
bind ssl vserver vs_web -cipherName grp_modern
bind ssl vserver vs_web -certkeyName wildcard_example_2026
bind ssl vserver vs_portal -certkeyName legacy_portal
bind ssl vserver vs_empty -eccCurveName P_256
add cs action cs_act_api -targetLBVserver vs_api
add cs action cs_act_missing -targetLBVserver vs_gone
add cs policy cs_pol_api -rule "HTTP.REQ.HOSTNAME.EQ(\"api.example.com\")" -action cs_act_api
add cs policy cs_pol_old -rule "HTTP.REQ.URL.STARTSWITH(\"/old\")" -action cs_act_missing
add cs vserver cs_public SSL 10.10.20.20 443 -cltTimeout 180
bind cs vserver cs_public vs_web
bind cs vserver cs_public -policyName cs_pol_api -priority 100
bind cs vserver cs_public -targetLBVserver vs_gone -policyName cs_pol_old -priority 200
bind ssl vserver cs_public -certkeyName wildcard_example_2026
add authentication ldapAction ldap_corp -serverIP 10.10.0.30 -serverPort 389 -ldapBase "dc=corp,dc=example,dc=com" -ldapBindDn "svc_adc@corp.example.com" -ldapBindDnPassword "5b2d8e7c1a9f4d3e6b0a7c8d9e1f2a3b" -encrypted -encryptmethod ENCMTHD_3 -ldapLoginName sAMAccountName -groupAttrName memberOf -subAttributeName cn
add authentication radiusAction rad_mfa -serverIP 10.10.0.31 -serverPort 1812 -radKey "EXAMPLE-NOT-A-REAL-KEY"
add authentication Policy pol_ldap -rule true -action ldap_corp
add authentication vserver auth_vs SSL 0.0.0.0
bind authentication vserver auth_vs -policy pol_ldap -priority 100
bind ssl vserver auth_vs -certkeyName wildcard_example_2026
add vpn sessionAction act_web_profile -defaultAuthorizationAction ALLOW -SSO ON -icaProxy ON -wihome "https://apps.example.com/Citrix/StoreWeb"
add vpn sessionPolicy pol_web_profile "HTTP.REQ.HEADER(\"User-Agent\").NOTCONTAINS(\"CitrixReceiver\")" act_web_profile
add vpn vserver gw_public SSL 10.10.20.30 443 -icaOnly ON -authnVsName auth_vs -downStateFlush DISABLED
bind vpn vserver gw_public -policyName pol_web_profile -priority 100
bind ssl vserver gw_public -certkeyName wildcard_example_2026
add audit syslogAction syslog_main 10.10.0.60 -logLevel ALL
add gslb site site_a LOCAL 10.10.20.40
set ns tcpProfile nstcp_default_profile -WS ENABLED
bind tm global
add ns notrafficdomain foo
`;