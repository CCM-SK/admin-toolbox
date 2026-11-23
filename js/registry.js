/**
 * Single source of truth for tool metadata, lazy loaders, examples and workflow adapters.
 * All modules are relative static assets, so GitHub Pages can serve them without a backend.
 */
const define = (id, name, category, description, path, exportName, options = {}) => ({
  id, name, category, description, modulePath: path, rendererName: exportName,
  load: async () => {
    const module = await import(path);
    if (typeof module[exportName] !== 'function') {
      throw new Error(`Tool renderer ${exportName} was not found for ${id}.`);
    }
    return module[exportName];
  },
  ...options
});

export const TOOL_REGISTRY = [
  define('dashboard', 'Home', 'Home', 'Overview, privacy model and quick access', './dashboard.js', 'renderDashboard'),

  define('logs', 'Log / CSV inspector', 'Diagnostics', 'Search, filter and export CSV or plain-text logs', './tools/logs.js', 'renderLogs', {
    example: { values: [{ selector: '#logPaste', value: '2026-10-12T08:15:23Z INFO host=web01 user=alice request=/health status=200\n2026-10-12T08:16:02Z WARN host=web01 user=alice request=/login status=401\n2026-10-12T08:17:11Z ERROR host=db01 process=sqlservr.exe message="connection timeout"' }], runSelector: '#logLoadText' },
    workflowSource: '#logPaste', workflowTarget: { selector: '#logPaste', runSelector: '#logLoadText' }
  }),
  define('eventviewer', 'Event Viewer analyzer', 'Diagnostics', 'Inspect exported Windows event data', './tools/eventviewer.js', 'renderEventViewer', { example: { values: [{ selector: '#eventInput', value: '<Event><System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/><EventID>4625</EventID><Level>2</Level><TimeCreated SystemTime=\"2026-10-12T08:16:02.000Z\"/><Computer>web01.example.test</Computer></System><EventData><Data Name=\"TargetUserName\">alice</Data><Data Name=\"IpAddress\">192.0.2.10</Data></EventData></Event>' }], runSelector: '#analyzeEvents' }, workflowSource: '#eventInput', workflowTarget: { selector: '#eventInput', runSelector: '#analyzeEvents' } }),
  define('diff', 'Configuration diff', 'Diagnostics', 'Compare two configuration texts or files', './tools/diffRewrite.js', 'renderDiff', {
    example: { values: [{ selector: '#a', value: 'service:\n  port: 8080\n  tls: false\n  timeout: 30' }, { selector: '#b', value: 'service:\n  port: 8443\n  tls: true\n  timeout: 30' }], runSelector: '#go' },
    workflowSource: '#a'
  }),
  define('hash', 'File hashing', 'Diagnostics', 'Calculate file hashes locally', './tools/hash.js', 'renderHash'),
  define('archivem', 'Archive manifest viewer', 'Diagnostics', 'Inspect archive metadata without extracting files', './tools/archivem.js', 'renderArchiveM'),
  define('jsonviewer', 'JSON Viewer', 'Diagnostics', 'Inspect and format JSON data', './tools/jsonviewer.js', 'renderJsonViewer', { example: { runSelector: '#jsonViewerLoadExample' }, workflowSource: '#jsonViewerInput', workflowTarget: { selector: '#jsonViewerInput', runSelector: '#jsonViewerAnalyze' } }),
  define('timeline', 'Structured log timeline', 'Diagnostics', 'Merge supported logs into a normalized timeline', './tools/timeline.js', 'renderTimeline', {
    example: { values: [{ selector: '#timelinePaste', value: '2026-10-12T08:15:23Z host=web01 user=alice ip=192.0.2.10 process=w3wp.exe request=/health\n2026-10-12T08:18:12Z host=db01 user=svc_app ip=192.0.2.20 process=sqlservr.exe message="login failed"' }], runSelector: '#timelineLoadPasted' },
    workflowSource: '#timelinePaste', workflowTarget: { selector: '#timelinePaste', runSelector: '#timelineLoadPasted' }
  }),

  define('passwords', 'Password generator', 'Security & identity', 'Generate random passwords and passphrases', './tools/passwords.js', 'renderPasswords'),
  define('sshare', 'Secure Share Password', 'Security & identity', 'Encrypt secrets locally for out-of-band sharing', './tools/sshare.js', 'renderSShare'),
  define('identityMeta', 'SID/GUID Meta Decoder', 'Security & identity', 'Decode common SID, GUID and identity metadata', './tools/identityMeta.js', 'renderIdentityMeta', { example: { values: [{ selector: '#identityInput', value: 'S-1-5-21-1111111111-2222222222-3333333333-1107\nS-1-5-32-544' }], runSelector: '#identityDecode' }, workflowSource: '#identityInput', workflowTarget: { selector: '#identityInput', runSelector: '#identityDecode' } }),
  define('identity', 'SID/GUID Decoder', 'Security & identity', 'Parse Windows SIDs and GUID representations', './tools/identity.js', 'renderIdentity', { example: { values: [{ selector: '#identityInput', value: 'S-1-5-21-1111111111-2222222222-3333333333-1107\n550e8400-e29b-41d4-a716-446655440000' }], runSelector: '#identityDecode' }, workflowSource: '#identityInput', workflowTarget: { selector: '#identityInput', runSelector: '#identityDecode' } }),
  define('certs', 'Certificate / CSR inspector', 'Security & identity', 'Inspect PEM and DER ASN.1 certificate or CSR content', './tools/certs.js', 'renderCerts'),
  define('sdetector', 'Secrets Detector', 'Security & identity', 'Find likely secrets and redact findings locally', './tools/sdetector.js', 'renderSDetector', {
    example: { values: [{ selector: '#sdInput', value: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAPI_ENDPOINT=https://api.example.invalid\nGITHUB_TOKEN=ghp_12345678901234567890example' }], runSelector: '#sdScan' },
    workflowSource: '#sdInput', workflowTarget: { selector: '#sdInput', runSelector: '#sdScan' }
  }),
  define('jwt', 'JWT/JWS/JWK Decoder', 'Security & identity', 'Decode JWT/JWS headers, claims and JWK metadata (no signature verification)', './tools/jwt.js', 'renderJwt', {
    example: { values: [{ selector: '#jwt-input', value: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJvcHMiLCJpYXQiOjE3MDAwMDAwMDB9.c2FtcGxlLXNpZ25hdHVyZQ' }], runSelector: '#jwt-decode' },
    workflowTarget: { selector: '#jwt-input', runSelector: '#jwt-decode' }
  }),

  define('headerrework', 'Mail-header analyzer', 'Network & firewall', 'Analyze message headers and delivery hops', './tools/headerrework.js', 'renderHeaderRework', { example: { values: [{ selector: '#mailHeaders', value: 'From: Alice Example <alice@example.test>\nTo: Bob Example <bob@example.test>\nSubject: Example delivery\nDate: Mon, 12 Oct 2026 08:15:23 +0000\nMessage-ID: <example-1@example.test>\nReceived: from mail.example.test (mail.example.test [192.0.2.10]) by mx.example.test; Mon, 12 Oct 2026 08:15:24 +0000\nAuthentication-Results: mx.example.test; spf=pass smtp.mailfrom=example.test; dkim=pass header.d=example.test; dmarc=pass header.from=example.test' }], runSelector: '#mailHeaderAnalyze' }, workflowSource: '#mailHeaders', workflowTarget: { selector: '#mailHeaders', runSelector: '#mailHeaderAnalyze' } }),
  define('urlanalyzer', 'URL Analyzer', 'Network & firewall', 'Inspect URL components, parameters and indicators', './tools/urlanalyzer.js', 'renderUrlAnalyzer', {
    example: { values: [{ selector: '#urlInput', value: 'https://portal.example.test/login?next=%2Fadmin&source=email' }], runSelector: '#analyzeUrl' },
    workflowSource: '#urlInput', workflowTarget: { selector: '#urlInput', runSelector: '#analyzeUrl' }
  }),
  define('subnet', 'IP/subnet calculator', 'Network & firewall', 'Calculate IPv4 and IPv6 network details', './tools/subnet.js', 'renderSubnet', {
    example: { values: [{ selector: '#cidr', value: '192.0.2.17/24' }], runSelector: '#calc' }
  }),
  define('range', 'IP Range Analyzer', 'Network & firewall', 'Analyze address ranges and overlaps', './tools/range.js', 'renderRangeAnalyzer', { example: { runSelector: '#range-example' }, workflowSource: '#range-input', workflowTarget: { selector: '#range-input', runSelector: '#range-analyze' } }),
  define('vlanplanner', 'VLAN planner', 'Network & firewall', 'Plan VLANs and subnets', './tools/vlanplanner.js', 'renderVlanPlanner', { example: { values: [{ selector: '#vpBase', value: '10.20.0.0/16' }, { selector: '#vpCount', value: '8' }, { selector: '#vpStartId', value: '100' }, { selector: '#vpHosts', value: '50' }, { selector: '#vpReserve', value: '2' }], runSelector: '#vpPlan' } }),
  define('route', 'Route Calculator/Simulator', 'Network & firewall', 'Analyze routing and network paths', './tools/route.js', 'renderRoute', {
    example: { values: [{ selector: '#routeDestination', value: '10.20.30.45' }, { selector: '#routeTableInput', value: 'Destination       Next Hop        Interface   Metric   Type\n0.0.0.0/0          192.168.1.1     eth0        100      static\n10.0.0.0/8         10.0.0.1        eth1        10       static\n10.20.0.0/16       10.20.0.1       eth2        20       static\n10.20.30.0/24      10.20.30.1      eth3        50       static' }], runSelector: '#routeCalculate' },
    workflowSource: '#routeTableInput', workflowTarget: { selector: '#routeTableInput', runSelector: '#routeCalculate' }
  }),
  define('ciscofirewall', 'Cisco ASA/ACL Analyzer', 'Network & firewall', 'Parse Cisco ASA and ACL rules', './tools/ciscoacl.js', 'renderCiscoFirewall', { example: { runSelector: '#cisco-fw-example' }, workflowSource: '#cisco-fw-input', workflowTarget: { selector: '#cisco-fw-input', runSelector: '#cisco-fw-analyze' } }),
  define('paloalto', 'Palo Alto Analyzer', 'Network & firewall', 'Inspect Palo Alto configuration exports', './tools/paloaltoRewrite.js', 'renderPaloAlto', {
    example: { values: [{ selector: '#paloAltoInput', value: 'set rulebase security rules Allow-DNS from Trust to Untrust source any destination any application dns service application-default action allow' }], runSelector: '#paloAltoAnalyze' },
    workflowSource: '#paloAltoInput', workflowTarget: { selector: '#paloAltoInput', runSelector: '#paloAltoAnalyze' }
  }),
  define('citrixadc', 'Citrix ADC Analyzer', 'Network & firewall', 'Parse Citrix ADC ns.conf configuration', './tools/citrixadc.js', 'renderCitrixAdc', {
    example: { runSelector: '#cxExample' },
    workflowSource: '#cxInput', workflowTarget: { selector: '#cxInput', runSelector: '#cxAnalyze' }
  }),
  define('cookies', 'Cookie Analyzer', 'Network & firewall', 'Inspect cookie attributes and security flags', './tools/cookies.js', 'renderCookies', {
    example: { values: [{ selector: '#cookieInput', value: 'sessionid=example-session; Path=/; Secure; HttpOnly; SameSite=Lax\npreferences=theme-dark; Path=/; SameSite=None' }], runSelector: '#cookieAnalyze' },
    workflowSource: '#cookieInput', workflowTarget: { selector: '#cookieInput', runSelector: '#cookieAnalyze' }
  }),

  define('regex', 'Regex Workbench', 'Developer & data', 'Test JavaScript regular expressions and replacements', './tools/regex.js', 'renderRegex', {
    example: { values: [{ selector: '#rxPattern', value: '(ERROR|WARN)' }, { selector: '#rxFlags', value: 'g' }, { selector: '#rxText', value: 'INFO startup complete\nWARN retrying connection\nERROR database unavailable' }], runSelector: '#rxRun' },
    workflowSource: '#rxText', workflowTarget: { selector: '#rxText', runSelector: '#rxRun' }
  }),
  define('encoding', 'Encoding/decoding', 'Developer & data', 'Encode and decode common text formats', './tools/encoding.js', 'renderEncoding', { example: { values: [{ selector: '#encoding-source', value: 'Local-only example: café / admin toolbox' }], runSelector: '#encoding-convert' }, workflowSource: '#encoding-source', workflowTarget: { selector: '#encoding-source', runSelector: '#encoding-convert' } }),
  define('dataWorkbench', 'Data Workbench', 'Developer & data', 'Convert, inspect and transform JSON, YAML and XML', './tools/jsonyamlxml.js', 'renderDataWorkbench', {
    example: { values: [{ selector: '#dw-input', value: '{\n  "environment": "test",\n  "service": "portal",\n  "replicas": 3\n}' }] , runSelector: '#dw-run' },
    workflowSource: '#dw-input', workflowTarget: { selector: '#dw-input', runSelector: '#dw-run' }
  }),
  define('dlls', 'DLL Analyzer', 'Developer & data', 'Inspect Windows DLL metadata and dependencies', './tools/dlls.js', 'renderDllAnalyzer'),
  define('timestamp', 'Timestamp converter', 'Developer & data', 'Convert timestamps and time zones', './tools/timestamp.js', 'renderTimestamp', { example: { values: [{ selector: '#ts-input', value: '1724064000' }], runSelector: '#ts-convert' } }),
  define('chmod', 'CHMOD Calculator/Parser', 'Developer & data', 'Convert Unix file permission representations', './tools/chmod.js', 'renderChmod', { example: { runSelector: '#chmod-example' } }),
  define('powershell', 'PowerShell Analyzer', 'Developer & data', 'Review PowerShell scripts for common issues', './tools/powershell.js', 'renderPowershell', {
    example: { values: [{ selector: '#psCode', value: 'Get-LocalUser | Where-Object Enabled -eq $true | Select-Object Name,LastLogon\n\nInvoke-Expression $userInput' }], runSelector: '#psAnalyze' },
    workflowSource: '#psCode', workflowTarget: { selector: '#psCode', runSelector: '#psAnalyze' }
  }),
  define('saplandscape', 'SAP Landscape Analyzer', 'Developer & data', 'Inspect SAP landscape exports and configuration', './tools/saplandscape.js', 'renderSapLandscape', { example: { runSelector: '#sapLandscapeExample' }, workflowSource: '#sapLandscapeInput', workflowTarget: { selector: '#sapLandscapeInput', runSelector: '#sapLandscapeAnalyze' } }),
  define('docker', 'Docker/Kubernetes Analyzer', 'Developer & data', 'Review Compose and Kubernetes manifests', './tools/docker.js', 'renderDockerKubernetes', {
    example: { runSelector: '#dkExampleCompose' },
    workflowSource: '#dkInput', workflowTarget: { selector: '#dkInput', runSelector: '#dkAnalyze' }
  }),

  define('gpresult', 'Group Policy Results', 'Windows & hardware', 'Inspect gpresult reports and policy settings', './tools/gpresult.js', 'renderGpResult', { example: { values: [{ selector: '#gp-input', value: 'Computer\nApplied Group Policy Objects\n    Default Domain Policy\n\nUser\nApplied Group Policy Objects\n    Workstation Baseline' }], runSelector: '#gp-analyze' }, workflowSource: '#gp-input', workflowTarget: { selector: '#gp-input', runSelector: '#gp-analyze' } }),
  define('drivers', 'Driver Assistant', 'Windows & hardware', 'Inspect driver inventory exports', './tools/drivers.js', 'renderDrivers'),
  define('bios', 'BIOS Interpreter', 'Windows & hardware', 'Interpret BIOS and hardware inventory data', './tools/bios.js', 'renderBiosInterpreter', { example: { runSelector: '#bios-example' } }),
  define('dism', 'DISM/Windows Image Inspector', 'Windows & hardware', 'Inspect DISM and Windows image output', './tools/dism.js', 'renderDism', { example: { runSelector: '#dismExample' }, workflowSource: '#dismInput', workflowTarget: { selector: '#dismInput', runSelector: '#dismAnalyze' } }),
  define('sddl', 'SDDL/ACL Inspector', 'Windows & hardware', 'Inspect security descriptor strings', './tools/sddl.js', 'renderSddl', { example: { values: [{ selector: '#sddlInput', value: 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)' }], runSelector: '#sddlAnalyze' }, workflowSource: '#sddlInput', workflowTarget: { selector: '#sddlInput', runSelector: '#sddlAnalyze' } }),

  define('cron_const', 'Cron Expression Builder', 'Automation', 'Build and explain cron expressions', './tools/cron_const.js', 'renderCronConst'),
  define('audit', 'Audit / architecture', 'Administration', 'Review security posture, tool inventory and deployment model', './tools/audit.js', 'renderAudit')
];

export const TOOL_BY_ID = new Map(TOOL_REGISTRY.map(tool => [tool.id, tool]));
export const TOOL_CATEGORIES = [...new Set(TOOL_REGISTRY.filter(tool => !['dashboard', 'audit'].includes(tool.id)).map(tool => tool.category))];
export function getTool(id) { return TOOL_BY_ID.get(id) || TOOL_BY_ID.get('dashboard'); }
