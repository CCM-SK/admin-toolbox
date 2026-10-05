import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';

export const metadata = {
  id: 'paloalto',
  title: 'Palo Alto Config Analyzer',
  description: 'Parse Palo Alto Networks PAN-OS configurations and security rule exports locally',
  path: '/#paloalto'
};

export function renderPaloAlto(app) {
  app.innerHTML = `
    <div class="tool-window" id="paloAltoWindow">
      <div class="tool-window-header" id="paloAltoDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>Palo Alto Networks Config Analyzer</strong>
        <span class="small" style="margin-left:auto"></span>
      </div>
      <section class="card">
        <p class="small">
          Paste a PAN-OS configuration, <code>show</code>/<code>set</code> output,
          or a Security Policy rule export. The parser works entirely in the browser.
          No configuration data is uploaded or sent to external services.
        </p>
        <textarea id="paloAltoInput" spellcheck="false"
          placeholder="Examples:
set rulebase security rules Allow-DNS from Trust to Untrust source any destination any application dns service application-default action allow or paste a PAN-OS XML configuration export here..."></textarea>
        <div class="row" style="margin-top:10px">
          <input id="paloAltoFile" type="file"
            accept=".xml,.txt,.csv,.json,.conf,.cfg,.log" hidden>
          <button class="btn" id="paloAltoPick">Load config / export</button>
          <button class="btn primary" id="paloAltoAnalyze">Analyze</button>
          <button class="btn" id="paloAltoClear">Clear</button>
          <button class="btn" id="paloAltoExport" disabled>Export analysis JSON</button>
        </div>
        <div id="paloAltoFileInfo" class="small" style="margin-top:10px"></div>
      </section>
      <section class="card" id="paloAltoResult" hidden></section>
    </div>
  `;

  enableToolDragging(
    $('#paloAltoWindow'),
    $('#paloAltoDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );

  let lastAnalysis = null;

  $('#paloAltoPick').onclick = () => $('#paloAltoFile').click();

  $('#paloAltoFile').onchange = async e => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await readLocalFile(file);
      $('#paloAltoInput').value = text;
      $('#paloAltoFileInfo').textContent =
        `Loaded ${file.name} locally (${text.length.toLocaleString()} characters).`;
    } catch (err) {
      $('#paloAltoFileInfo').textContent = '';
      showError(err.message || 'The file could not be read.');
    }
  };

  $('#paloAltoClear').onclick = () => {
    $('#paloAltoInput').value = '';
    $('#paloAltoFile').value = '';
    $('#paloAltoFileInfo').textContent = '';
    $('#paloAltoResult').hidden = true;
    $('#paloAltoResult').innerHTML = '';
    $('#paloAltoExport').disabled = true;
    lastAnalysis = null;
  };
  $('#paloAltoAnalyze').onclick = analyze;
  $('#paloAltoInput').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze();
  });
  $('#paloAltoExport').onclick = () => {
    if (!lastAnalysis) return;
    downloadText(
      'paloalto-config-analysis.json',
      JSON.stringify(lastAnalysis, null, 2),
      'application/json;charset=utf-8'
    );
  };

  function analyze() {
    const raw = $('#paloAltoInput').value;
    const result = $('#paloAltoResult');
    if (!raw.trim()) {
      result.hidden = false;
      result.innerHTML =
        `<div class="status warning">Paste a Palo Alto Networks configuration or rule export first.</div>`;
      return;
    }
    try {
      lastAnalysis = analyzePaloAlto(raw);
      result.hidden = false;
      result.innerHTML = renderAnalysis(lastAnalysis);
      $('#paloAltoExport').disabled = false;
    } catch (err) {
      showError(err.message || 'Palo Alto configuration parsing failed.');
    }
  }
  function showError(message) {
    const result = $('#paloAltoResult');
    result.hidden = false;
    result.innerHTML =
      `<div class="status danger">${escapeHtml(message)}</div>`;
  }
}

function analyzePaloAlto(raw) {
  const text = String(raw || '').replace(/^\uFEFF/, '');
  const format = detectFormat(text);

  if (format === 'xml') {
    const parsed = parseXmlConfig(text);
    const findings = analyzeXmlConfiguration(parsed);
    const stats = buildXmlStats(parsed, findings);

    return {
      note:
        'Local-only Palo Alto Networks PAN-OS configuration analysis. ' +
        'No DNS, threat intelligence, WildFire, cloud lookup, or remote service is used.',
      format,
      metadata: parsed.metadata,
      stats,
      rules: parsed.securityRules,
      objects: parsed.objects,
      interfaces: parsed.interfaces,
      zones: parsed.zones,
      findings,
      configuration: parsed.configuration,
      coverage: parsed.coverage,
      inventory: parsed.inventory,
      generatedAt: new Date().toISOString()
    };
  }

  let rules = [];
  let objects = [];
  let interfaces = [];
  let zones = [];
  let metadata = {};

  if (format === 'set') {
    ({ rules, objects, interfaces, zones, metadata } = parseSetConfig(text));
  } else if (format === 'csv') {
    rules = parseRuleCsv(text);
  } else {
    ({ rules, objects, interfaces, zones, metadata } = parseTextShow(text));
  }

  const findings = analyzeRules(rules);
  const stats = buildStats(rules, findings);

  return {
    note:
      'Local-only Palo Alto Networks PAN-OS configuration analysis. ' +
      'This tool does not contact Palo Alto, DNS, threat intelligence, or any remote service.',
    format,
    metadata,
    stats,
    rules,
    objects,
    interfaces,
    zones,
    findings,
    coverage: null,
    inventory: [],
    generatedAt: new Date().toISOString()
  };
}

function detectFormat(text) {
  const t = text.trim();
  if (/^<\?xml\b|^<config[\s>]/i.test(t) || /<security><rules>/i.test(t)) return 'xml';
  if (/^\s*set\s+(?:deviceconfig|rulebase|vsys|shared|network)\b/im.test(text)) {
    return 'set';
  }

  const firstLines = t.split(/\r?\n/).slice(0, 8);
  if (firstLines.some(x => /(?:^|,)rule(?:name)?(?:,|$)/i.test(x)) ||
      firstLines.some(x => /from,to,source,destination,application/i.test(x))) {
    return 'csv';
  }

  return 'text';
}

function parseXmlConfig(text) {
  const doc = parseXmlDocument(text);
  const root = doc.documentElement;

  const ctx = {
    doc,
    root,
    findings: [],
    inventory: buildXmlInventory(root),

    metadata: {},

    configuration: {
      management: {},
      shared: {},
      devices: {},
      templates: [],
      templateStacks: [],
      state: {}
    },

    securityRules: [],
    objects: [],
    interfaces: [],
    zones: [],

    coveredRoots: new Set()
  };

  parseXmlMetadata(ctx);
  parseXmlManagement(ctx);
  parseXmlShared(ctx);
  parseXmlDevices(ctx);
  parseXmlTemplates(ctx);
  parseXmlState(ctx);

  const duplicateFindings = detectXmlDuplicateEntries(ctx);
  const referenceFindings = detectXmlReferences(ctx);
  const validationFindings = validateXmlConfiguration(ctx);

  ctx.findings.push(
    ...duplicateFindings,
    ...referenceFindings,
    ...validationFindings
  );

  const coverage = buildXmlCoverage(ctx);

  return {
    metadata: ctx.metadata,
    securityRules: ctx.securityRules,
    objects: ctx.objects,
    interfaces: ctx.interfaces,
    zones: ctx.zones,
    findings: dedupeFindings(ctx.findings),
    configuration: ctx.configuration,
    coverage,
    inventory: ctx.inventory
  };
}

function parseXmlDocument(text) {
  let doc;
  try {
    doc = new DOMParser().parseFromString(text, 'application/xml');
  } catch {
    throw new Error('The browser could not parse the XML configuration.');
  }
  if (!doc?.documentElement) {
    throw new Error('The XML document has no root element.');
  }
  if (doc.querySelector('parsererror')) {
    throw new Error('The XML configuration is malformed or incomplete.');
  }
  if (localName(doc.documentElement) !== 'config') {
    throw new Error(
      `Expected a <config> root element; found <${localName(doc.documentElement)}>.`
    );
  }
  return doc;
}

function parseXmlMetadata(ctx) {
  const root = ctx.root;
  ctx.metadata.configVersion = attr(root, 'version');
  ctx.metadata.serial = attr(root, 'serial');
  ctx.metadata.panOsVersion =
    firstTextAt(ctx.root, [
      ['readonly', 'devices', 'entry', 'sw-version'],
      ['devices', 'entry', 'deviceconfig', 'system', 'sw-version'],
      ['sw-version']
    ]) ||
    ctx.metadata.configVersion ||
    '';
  ctx.metadata.hostname =
    firstTextAt(ctx.root, [
      ['devices', 'entry', 'deviceconfig', 'system', 'hostname'],
      ['hostname']
    ]) || '';
  ctx.coveredRoots.add('config');
}

function parseXmlManagement(ctx) {
  const node = firstPath(ctx.root, ['mgt-config']);
  if (!node) return;

  ctx.coveredRoots.add('mgt-config');

  const management = ctx.configuration.management;

  const users = childEntries(firstPath(node, ['users']));
  management.users = users.map(entry => ({
    ...recordEntry(entry, 'management-user'),
    superuser: textAt(entry, ['permissions', 'role-based', 'superuser']),
    vsysAdmins: valuesAt(
      entry,
      ['permissions', 'role-based', 'vsysadmin']
    )
  }));

  const passwordComplexity =
    firstPath(node, ['password-complexity']);

  management.passwordComplexity =
    passwordComplexity
      ? flattenXml(passwordComplexity)
      : null;
}

function parseXmlShared(ctx) {
  const shared = firstPath(ctx.root, ['shared']);
  if (!shared) return;

  ctx.coveredRoots.add('shared');

  const out = ctx.configuration.shared;

  out.addresses = parseNamedEntries(
    firstPath(shared, ['address']),
    'address',
    entry => {
      const ipNetmask = attr(entry, 'ip-netmask');
      const fqdn = textAt(entry, ['fqdn']);

      return recordEntry(entry, 'address', {
        value: ipNetmask || fqdn || '',
        ipNetmask,
        fqdn,
        scope: 'shared'
      });
    }
  );

  out.addressGroups = parseNamedEntries(
    firstPath(shared, ['address-group']),
    'address-group',
    entry => recordEntry(entry, 'address-group', {
      scope: 'shared',
      mode: hasPath(entry, ['static'])
        ? 'static'
        : hasPath(entry, ['dynamic'])
          ? 'dynamic'
          : 'unknown',
      members: valuesAt(entry, ['static', 'member']),
      filter: textAt(entry, ['dynamic', 'filter'])
    })
  );

  out.services = parseNamedEntries(
    firstPath(shared, ['service']),
    'service',
    entry => recordEntry(entry, 'service', {
      scope: 'shared',
      protocols: parseServiceProtocols(entry)
    })
  );

  out.serviceGroups = parseNamedEntries(
    firstPath(shared, ['service-group']),
    'service-group',
    entry => recordEntry(entry, 'service-group', {
      scope: 'shared',
      members: valuesAt(entry, ['members', 'member'])
    })
  );

  out.applications = parseNamedEntries(
    firstPath(shared, ['application']),
    'application',
    entry => recordEntry(entry, 'application', {
      scope: 'shared',
      category: textAt(entry, ['category']),
      subcategory: textAt(entry, ['subcategory']),
      technology: textAt(entry, ['technology']),
      risk: numberValue(textAt(entry, ['risk'])),
      evasive: textAt(entry, ['evasive'])
    })
  );

  out.applicationGroups = parseNamedEntries(
    firstPath(shared, ['application-group']),
    'application-group',
    entry => recordEntry(entry, 'application-group', {
      scope: 'shared',
      members:
        valuesAt(entry, ['members', 'member'])
          .concat(valuesAt(entry, ['static', 'member']))
    })
  );

  out.applicationFilters = parseNamedEntries(
    firstPath(shared, ['application-filter']),
    'application-filter',
    entry => recordEntry(entry, 'application-filter', {
      scope: 'shared'
    })
  );

  out.tags = parseNamedEntries(
    firstPath(shared, ['tag']),
    'tag',
    entry => recordEntry(entry, 'tag', {
      scope: 'shared',
      color: textAt(entry, ['color'])
    })
  );

  const logSettings = firstPath(shared, ['log-settings']);
  out.logSettings = logSettings
    ? flattenXml(logSettings)
    : null;

  ctx.objects.push(
    ...out.addresses,
    ...out.addressGroups,
    ...out.services,
    ...out.serviceGroups,
    ...out.applications,
    ...out.applicationGroups,
    ...out.applicationFilters
  );
}

function parseXmlDevices(ctx) {
  const devices = firstPath(ctx.root, ['devices']);
  if (!devices) return;

  ctx.coveredRoots.add('devices');

  for (const deviceEntry of childEntries(devices)) {
    const deviceName =
      attr(deviceEntry, 'name') || '(unnamed-device)';

    const device = {
      name: deviceName,
      path: xmlPath(deviceEntry),

      deviceconfig: {},
      network: {
        interfaces: [],
        zones: [],
        virtualRouters: [],
        dhcp: [],
        dnsProxy: [],
        ike: {
          cryptoProfiles: {},
          gateways: [],
          ipsecTunnels: []
        },
        pbfRules: []
      },

      vsys: [],
      plugins: [],

      raw: flattenXml(deviceEntry)
    };

    const deviceConfig =
      firstPath(deviceEntry, ['deviceconfig']);

    if (deviceConfig) {
      device.deviceconfig = parseXmlDeviceConfig(
        deviceConfig
      );
    }

    const network =
      firstPath(deviceEntry, ['network']);

    if (network) {
      device.network =
        parseXmlNetwork(network, ctx, deviceName);
    }

    const vsys =
      firstPath(deviceEntry, ['vsys']);

    if (vsys) {
      device.vsys = childEntries(vsys).map(vsysEntry =>
        parseXmlVsys(vsysEntry, ctx, deviceName)
      );
    }

    const plugins =
      firstPath(deviceEntry, ['plugins']);

    if (plugins) {
      device.plugins = childEntries(plugins).map(entry =>
        recordEntry(entry, 'plugin', {
          scope: deviceName
        })
      );
    }

    ctx.configuration.devices[deviceName] = device;
  }
}

function parseXmlDeviceConfig(node) {
  const result = {
    system: firstPath(node, ['system'])
      ? flattenXml(firstPath(node, ['system']))
      : null,

    management: firstPath(node, ['config'])
      ? flattenXml(firstPath(node, ['config']))
      : null,

    serverProfiles: {}
  };

  const serverProfiles =
    firstPath(node, ['server-profile']);

  if (serverProfiles) {
    for (const child of elementChildren(serverProfiles)) {
      const type = localName(child);

      result.serverProfiles[type] =
        childEntries(child).map(entry =>
          recordEntry(entry, `${type}-server-profile`)
        );
    }
  }

  return result;
}

function parseXmlNetwork(node, ctx, deviceName) {
  const result = {
    interfaces: [],
    zones: [],
    virtualRouters: [],
    dhcp: [],
    dnsProxy: [],
    ike: {
      cryptoProfiles: {},
      gateways: [],
      ipsecTunnels: []
    },
    pbfRules: []
  };

  const interfaceRoot =
    firstPath(node, ['interface']);

  if (interfaceRoot) {
    const interfaceFamilies = [
      {
        container: 'ethernet',
        type: 'ethernet',
        entries: ['entry']
      },
      {
        container: 'aggregate-ethernet',
        type: 'aggregate-ethernet',
        entries: ['entry']
      },
      {
        container: 'vlan',
        type: 'vlan',
        entries: ['units', 'entry']
      },
      {
        container: 'loopback',
        type: 'loopback',
        entries: ['units', 'entry']
      },
      {
        container: 'tunnel',
        type: 'tunnel',
        entries: ['units', 'entry']
      }
    ];

    for (const family of interfaceFamilies) {
      const container =
        firstPath(interfaceRoot, [family.container]);

      if (!container) continue;

      const parent =
        family.entries.length === 1
          ? container
          : firstPath(
              container,
              family.entries.slice(0, -1)
            );

      for (const entry of childEntries(parent)) {
        const ips =
          entryNamesAt(entry, ['layer3', 'ip'])
            .concat(entryNamesAt(entry, ['ip']));

        const record = recordEntry(
          entry,
          family.type,
          {
            device: deviceName,
            type: family.type,
            layer:
              hasPath(entry, ['layer3'])
                ? 'layer3'
                : hasPath(entry, ['layer2'])
                  ? 'layer2'
                  : 'unit',
            ips,
            members:
              valuesAt(entry, ['interface', 'member'])
          }
        );

        record.tap =
          hasPath(entry, ['tap', 'yes']);

        result.interfaces.push(record);
        ctx.interfaces.push(record);
      }
    }
  }

  const zoneRoot =
    firstPath(node, ['zone']);

  if (zoneRoot) {
    for (const entry of childEntries(zoneRoot)) {
      const members =
        valuesAt(entry, ['network', 'layer3', 'member'])
          .concat(
            valuesAt(entry, ['network', 'layer2', 'member'])
          )
          .concat(
            valuesAt(entry, ['network', 'tunnel', 'member'])
          );

      const record = recordEntry(
        entry,
        'zone',
        {
          device: deviceName,
          mode:
            hasPath(entry, ['network', 'layer3'])
              ? 'layer3'
              : hasPath(entry, ['network', 'layer2'])
                ? 'layer2'
                : hasPath(entry, ['network', 'tunnel'])
                  ? 'tunnel'
                  : 'unknown',
          members,
          userIdentification:
            textAt(
              entry,
              ['enable-user-identification']
            )
        }
      );

      result.zones.push(record);
      ctx.zones.push(record);
    }
  }

  const virtualRouterRoot =
    firstPath(node, ['virtual-router']);

  if (virtualRouterRoot) {
    for (const entry of childEntries(virtualRouterRoot)) {
      const record = recordEntry(
        entry,
        'virtual-router',
        {
          device: deviceName,
          interfaces:
            valuesAt(entry, ['interface', 'member'])
        }
      );

      record.protocols =
        parseRoutingProtocols(
          firstPath(entry, ['protocol'])
        );

      record.staticRoutes =
        childEntries(
          firstPath(
            entry,
            ['routing-table', 'ip', 'static-route']
          )
        ).map(route => flattenXml(route));

      result.virtualRouters.push(record);
    }
  }

  const dhcpRoot =
    firstPath(node, ['dhcp']);

  if (dhcpRoot) {
    result.dhcp =
      childEntries(dhcpRoot).map(entry =>
        recordEntry(entry, 'dhcp-server')
      );
  }

  const dnsProxyRoot =
    firstPath(node, ['dns-proxy']);

  if (dnsProxyRoot) {
    result.dnsProxy =
      childEntries(dnsProxyRoot).map(entry =>
        recordEntry(entry, 'dns-proxy')
      );
  }

  const ikeRoot =
    firstPath(node, ['ike']);

  if (ikeRoot) {
    result.ike =
      parseIkeConfiguration(ikeRoot);
  }

  const pbfRoot =
    firstPath(node, ['pbf', 'rules']);

  if (pbfRoot) {
    result.pbfRules =
      childEntries(pbfRoot).map(entry => ({
        ...recordEntry(entry, 'pbf'),
        from: valuesAt(entry, ['from', 'member']),
        to: valuesAt(entry, ['to', 'member']),
        sourceAddresses:
          valuesAt(entry, ['source', 'member']),
        destinationAddresses:
          valuesAt(entry, ['destination', 'member']),
        applications:
          valuesAt(entry, ['application', 'member']),
        services:
          valuesAt(entry, ['service', 'member']),
        action:
          textAt(entry, ['action']),
        metric:
          numberValue(textAt(entry, ['metric']))
      }));
  }

  return result;
}

function parseRoutingProtocols(node) {
  if (!node) return {};

  return {
    bgp: firstPath(node, ['bgp'])
      ? flattenXml(firstPath(node, ['bgp']))
      : null,

    ospf: firstPath(node, ['ospf'])
      ? flattenXml(firstPath(node, ['ospf']))
      : null
  };
}

function parseIkeConfiguration(node) {
  const result = {
    cryptoProfiles: {},
    gateways: [],
    ipsecTunnels: []
  };

  const crypto =
    firstPath(node, ['crypto-profiles']);

  if (crypto) {
    result.cryptoProfiles.ike =
      childEntries(
        firstPath(
          crypto,
          ['ike-crypto-profiles']
        )
      ).map(entry =>
        recordEntry(entry, 'ike-crypto-profile')
      );

    result.cryptoProfiles.ipsec =
      childEntries(
        firstPath(
          crypto,
          ['ipsec-crypto-profiles']
        )
      ).map(entry =>
        recordEntry(entry, 'ipsec-crypto-profile')
      );
  }

  const gateways =
    firstPath(node, ['gateway']);

  if (gateways) {
    result.gateways =
      childEntries(gateways).map(entry =>
        recordEntry(entry, 'ike-gateway')
      );
  }

  const tunnels =
    firstPath(node, ['ipsec-tunnel']);

  if (tunnels) {
    result.ipsecTunnels =
      childEntries(tunnels).map(entry =>
        recordEntry(entry, 'ipsec-tunnel')
      );
  }

  return result;
}

/* -------------------------------------------------------------------------- */
/* VSYS                                                                       */
/* -------------------------------------------------------------------------- */

function parseXmlVsys(node, ctx, deviceName) {
  const vsysName =
    attr(node, 'name') || '(unnamed-vsys)';

  const vsys = {
    name: vsysName,
    device: deviceName,
    displayName:
      textAt(node, ['display-name']),

    imports: {
      interfaces:
        valuesAt(
          node,
          ['import', 'interface', 'member']
        ),
      zones:
        valuesAt(
          node,
          ['import', 'zone', 'member']
        )
    },

    objects: {},

    schedules: [],
    profiles: {},
    profileGroups: [],

    securityRules: [],
    natRules: [],
    qosRules: [],
    applicationOverrideRules: [],
    decryptionRules: [],

    certificates: [],
    authenticationProfiles: [],
    serverProfiles: {},

    globalProtect: {},
    userId: {},

    hipObjects: [],
    hipProfiles: [],

    raw: flattenXml(node)
  };

  const objectTypes = [
    'address',
    'address-group',
    'service',
    'service-group',
    'application-group',
    'application-filter'
  ];

  for (const type of objectTypes) {
    const container =
      firstPath(node, [type]);

    const records =
      parseNamedEntries(
        container,
        type,
        entry => {
          const record =
            recordEntry(
              entry,
              type,
              {
                scope: vsysName,
                device: deviceName
              }
            );

          if (type === 'address') {
            record.ipNetmask =
              attr(entry, 'ip-netmask');

            record.fqdn =
              textAt(entry, ['fqdn']);

            record.value =
              record.ipNetmask ||
              record.fqdn ||
              textAt(entry, ['value']) ||
              '';
          }

          if (type === 'address-group') {
            record.mode =
              hasPath(entry, ['static'])
                ? 'static'
                : hasPath(entry, ['dynamic'])
                  ? 'dynamic'
                  : 'unknown';

            record.members =
              valuesAt(
                entry,
                ['static', 'member']
              );

            record.filter =
              textAt(
                entry,
                ['dynamic', 'filter']
              );
          }

          if (type === 'service') {
            record.protocols =
              parseServiceProtocols(entry);
          }

          if (type === 'service-group') {
            record.members =
              valuesAt(
                entry,
                ['members', 'member']
              );
          }

          if (type === 'application-group') {
            record.members =
              valuesAt(
                entry,
                ['members', 'member']
              ).concat(
                valuesAt(
                  entry,
                  ['static', 'member']
                )
              );
          }

          return record;
        }
      );

    vsys.objects[type] = records;
    ctx.objects.push(...records);
  }

  const schedule =
    firstPath(node, ['schedule']);

  if (schedule) {
    vsys.schedules =
      childEntries(schedule).map(entry =>
        recordEntry(entry, 'schedule', {
          scope: vsysName,
          device: deviceName
        })
      );
  }

  const profiles =
    firstPath(node, ['profiles']);

  if (profiles) {
    vsys.profiles =
      parseVsysProfiles(
        profiles,
        vsysName,
        deviceName
      );
  }

  const profileGroup =
    firstPath(node, ['profile-group']);

  if (profileGroup) {
    vsys.profileGroups =
      childEntries(profileGroup).map(entry =>
        recordEntry(
          entry,
          'profile-group',
          {
            scope: vsysName,
            device: deviceName,
            references: {
              virus:
                textAt(entry, ['virus']),
              spyware:
                textAt(entry, ['spyware']),
              vulnerability:
                textAt(
                  entry,
                  ['vulnerability']
                ),
              urlFiltering:
                textAt(
                  entry,
                  ['url-filtering']
                ),
              fileBlocking:
                textAt(
                  entry,
                  ['file-blocking']
                ),
              wildfireAnalysis:
                textAt(
                  entry,
                  ['wildfire-analysis']
                ),
              dataFiltering:
                textAt(
                  entry,
                  ['data-filtering']
                )
            }
          }
        )
      );
  }

  const security =
    firstPath(
      node,
      ['rulebase', 'security', 'rules']
    );

  if (security) {
    vsys.securityRules =
      childEntries(security).map(
        (entry, index) => {
          const rule =
            parseSecurityRuleXml(
              entry,
              {
                scope: vsysName,
                device: deviceName,
                index: index + 1,
                rulebase: 'security'
              }
            );

          ctx.securityRules.push(rule);
          return rule;
        }
      );
  }

  const nat =
    firstPath(
      node,
      ['rulebase', 'nat', 'rules']
    );

  if (nat) {
    vsys.natRules =
      childEntries(nat).map(
        (entry, index) => ({
          ...parsePolicyRuleXml(
            entry,
            'nat',
            {
              scope: vsysName,
              device: deviceName,
              index: index + 1
            }
          ),
          sourceTranslation:
            firstPath(
              entry,
              ['source-translation']
            )
              ? flattenXml(
                  firstPath(
                    entry,
                    ['source-translation']
                  )
                )
              : null,
          destinationTranslation:
            firstPath(
              entry,
              ['destination-translation']
            )
              ? flattenXml(
                  firstPath(
                    entry,
                    ['destination-translation']
                  )
                )
              : null
        })
      );
  }

  const qos =
    firstPath(
      node,
      ['rulebase', 'qos', 'rules']
    );

  if (qos) {
    vsys.qosRules =
      childEntries(qos).map(
        (entry, index) => ({
          ...parsePolicyRuleXml(
            entry,
            'qos',
            {
              scope: vsysName,
              device: deviceName,
              index: index + 1
            }
          ),
          class:
            numberValue(
              textAt(entry, ['class'])
            ),
          actionDetails:
            flattenXml(
              firstPath(entry, ['action'])
            )
        })
      );
  }

  const override =
    firstPath(
      node,
      [
        'rulebase',
        'application-override',
        'rules'
      ]
    );

  if (override) {
    vsys.applicationOverrideRules =
      childEntries(override).map(
        (entry, index) => ({
          ...parsePolicyRuleXml(
            entry,
            'application-override',
            {
              scope: vsysName,
              device: deviceName,
              index: index + 1
            }
          ),
          port:
            textAt(entry, ['port'])
        })
      );
  }

  const decryption =
    firstPath(
      node,
      ['rulebase', 'decryption', 'rules']
    );

  if (decryption) {
    vsys.decryptionRules =
      childEntries(decryption).map(
        (entry, index) => ({
          ...parsePolicyRuleXml(
            entry,
            'decryption',
            {
              scope: vsysName,
              device: deviceName,
              index: index + 1
            }
          ),
          actionDetails:
            flattenXml(
              firstPath(entry, ['action'])
            )
        })
      );
  }

  const certificates =
    firstPath(node, ['certificate']);

  if (certificates) {
    vsys.certificates =
      childEntries(certificates).map(
        entry =>
          recordEntry(
            entry,
            'certificate',
            {
              scope: vsysName,
              device: deviceName,
              notAfter:
                textAt(entry, ['not-after']),
              hasPrivateKey:
                Boolean(
                  firstPath(
                    entry,
                    ['private-key']
                  )
                )
            }
          )
      );
  }

  const auth =
    firstPath(
      node,
      ['authentication-profile']
    );

  if (auth) {
    vsys.authenticationProfiles =
      childEntries(auth).map(
        entry =>
          recordEntry(
            entry,
            'authentication-profile',
            {
              scope: vsysName,
              device: deviceName
            }
          )
      );
  }

  const serverProfiles =
    firstPath(
      node,
      ['server-profile']
    );

  if (serverProfiles) {
    for (const child of elementChildren(serverProfiles)) {
      const key = localName(child);

      vsys.serverProfiles[key] =
        childEntries(child).map(
          entry =>
            recordEntry(
              entry,
              `${key}-server-profile`,
              {
                scope: vsysName,
                device: deviceName
              }
            )
        );
    }
  }

  const globalProtect =
    firstPath(node, ['global-protect']);

  if (globalProtect) {
    vsys.globalProtect = {
      portal:
        childEntries(
          firstPath(
            globalProtect,
            ['portal']
          )
        ).map(entry =>
          recordEntry(
            entry,
            'globalprotect-portal',
            {
              scope: vsysName,
              device: deviceName
            }
          )
        ),

      gateway:
        childEntries(
          firstPath(
            globalProtect,
            ['gateway']
          )
        ).map(entry =>
          recordEntry(
            entry,
            'globalprotect-gateway',
            {
              scope: vsysName,
              device: deviceName
            }
          )
        )
    };
  }

  const userId =
    firstPath(node, ['user-id']);

  if (userId) {
    vsys.userId = {
      collectorSettings:
        childEntries(
          firstPath(
            userId,
            ['collector-settings']
          )
        ).map(entry =>
          recordEntry(
            entry,
            'uid-collector',
            {
              scope: vsysName,
              device: deviceName
            }
          )
        ),

      groupMapping:
        childEntries(
          firstPath(
            userId,
            ['group-mapping']
          )
        ).map(entry =>
          recordEntry(
            entry,
            'uid-group-mapping',
            {
              scope: vsysName,
              device: deviceName
            }
          )
        )
    };
  }

  const hipObjects =
    firstPath(node, ['hip-objects']);

  if (hipObjects) {
    vsys.hipObjects =
      childEntries(hipObjects).map(entry =>
        recordEntry(
          entry,
          'hip-object',
          {
            scope: vsysName,
            device: deviceName
          }
        )
      );
  }

  const hipProfiles =
    firstPath(node, ['hip-profiles']);

  if (hipProfiles) {
    vsys.hipProfiles =
      childEntries(hipProfiles).map(entry =>
        recordEntry(
          entry,
          'hip-profile',
          {
            scope: vsysName,
            device: deviceName
          }
        )
      );
  }

  return vsys;
}

function parseVsysProfiles(node, scope, device) {
  const mappings = [
    ['url-filtering', 'urlFiltering'],
    ['virus', 'virus'],
    ['vulnerability', 'vulnerability'],
    ['spyware', 'spyware'],
    ['file-blocking', 'fileBlocking'],
    ['wildfire-analysis', 'wildfireAnalysis'],
    ['data-filtering', 'dataFiltering']
  ];

  const result = {};

  for (const [xmlName, key] of mappings) {
    const container =
      firstPath(node, [xmlName]);

    if (!container) continue;

    result[key] =
      childEntries(container).map(
        entry =>
          recordEntry(
            entry,
            key,
            {
              scope,
              device
            }
          )
      );
  }

  return result;
}

function parseSecurityRuleXml(node, context = {}) {
  const rule = recordEntry(
    node,
    'security-rule',
    context
  );

  rule.from =
    valuesAt(node, ['from', 'member']);

  rule.to =
    valuesAt(node, ['to', 'member']);

  rule.sourceAddresses =
    valuesAt(
      node,
      ['source', 'member']
    );

  rule.destinationAddresses =
    valuesAt(
      node,
      ['destination', 'member']
    );

  rule.applications =
    valuesAt(
      node,
      ['application', 'member']
    );

  rule.services =
    valuesAt(
      node,
      ['service', 'member']
    );

  rule.categories =
    valuesAt(
      node,
      ['category', 'member']
    );

  rule.users =
    valuesAt(
      node,
      ['source-user', 'member']
    );

  rule.tags =
    valuesAt(
      node,
      ['tag', 'member']
    );

  rule.action =
    textAt(node, ['action']) ||
    'unknown';

  rule.disabled =
    parseBoolean(
      textAt(node, ['disabled']),
      false
    );

  rule.logStart =
    parseBoolean(
      textAt(node, ['log-start']),
      false
    );

  rule.logEnd =
    parseBoolean(
      textAt(node, ['log-end']),
      false
    );

  rule.description =
    textAt(node, ['description']);

  rule.uuid =
    attr(node, 'uuid') ||
    textAt(node, ['uuid']);

  rule.ruleType =
    textAt(node, ['rule-type']) ||
    'universal';

  rule.negateSource =
    parseBoolean(
      textAt(node, ['negate-source']),
      false
    );

  rule.negateDestination =
    parseBoolean(
      textAt(node, ['negate-destination']),
      false
    );

  rule.profileGroups =
    valuesAt(
      node,
      [
        'profile-setting',
        'group',
        'member'
      ]
    );

  return rule;
}

function parsePolicyRuleXml(node, type, context = {}) {
  return {
    ...recordEntry(
      node,
      type,
      context
    ),

    from:
      valuesAt(node, ['from', 'member']),

    to:
      valuesAt(node, ['to', 'member']),

    sourceAddresses:
      valuesAt(
        node,
        ['source', 'member']
      ),

    destinationAddresses:
      valuesAt(
        node,
        ['destination', 'member']
      ),

    applications:
      valuesAt(
        node,
        ['application', 'member']
      ),

    services:
      valuesAt(
        node,
        ['service', 'member']
      )
  };
}

function parseXmlTemplates(ctx) {
  const devices =
    firstPath(ctx.root, ['devices']);

  if (!devices) return;

  const stacks = [];
  const templates = [];

  for (const device of childEntries(devices)) {
    const stack =
      firstPath(
        device,
        ['template-stack']
      );

    if (stack) {
      stacks.push(
        ...childEntries(stack).map(
          entry =>
            recordEntry(
              entry,
              'template-stack'
            )
        )
      );
    }

    const template =
      firstPath(
        device,
        ['template']
      );

    if (template) {
      templates.push(
        ...childEntries(template).map(
          entry =>
            recordEntry(
              entry,
              'template'
            )
        )
      );
    }
  }

  ctx.configuration.templateStacks = stacks;
  ctx.configuration.templates = templates;
}

function parseXmlState(ctx) {
  const state = ctx.configuration.state;

  const readonly =
    firstPath(ctx.root, ['readonly']);

  if (readonly) {
    state.readonly =
      flattenXml(readonly);
  }

  const locks =
    firstPath(ctx.root, ['config-locks']);

  if (locks) {
    state.configLocks =
      childEntries(locks).map(
        entry =>
          recordEntry(
            entry,
            'config-lock'
          )
      );
  }

  const audit =
    firstPath(ctx.root, ['audit']);

  if (audit) {
    state.audit =
      childEntries(audit).map(
        entry =>
          recordEntry(
            entry,
            'audit'
          )
      );
  }

  ctx.coveredRoots.add('readonly');
  ctx.coveredRoots.add('config-locks');
  ctx.coveredRoots.add('audit');
}

function detectXmlDuplicateEntries(ctx) {
  const findings = [];
  const buckets = new Map();

  walkElements(ctx.root, node => {
    if (localName(node) !== 'entry') return;

    const name = attr(node, 'name');
    const parent = node.parentElement;

    if (!name || !parent) return;

    const key =
      `${xmlPath(parent)}::${name}`;

    const list =
      buckets.get(key) || [];

    list.push(node);
    buckets.set(key, list);
  });

  for (const [key, entries] of buckets) {
    if (entries.length < 2) continue;

    findings.push({
      severity: 'warn',
      rule:
        attr(entries[0], 'name') ||
        '(unnamed)',
      code: 'DUPLICATE_XML_ENTRY',
      text:
        `Duplicate XML entry name "${attr(entries[0], 'name')}" ` +
        `occurs ${entries.length} times under ${key.split('::')[0]}.`
    });
  }

  return findings;
}

function detectXmlReferences(ctx) {
  const findings = [];

  const addressObjects =
    ctx.objects.filter(
      x =>
        x.type === 'address' ||
        x.type === 'address-group'
    );

  const serviceObjects =
    ctx.objects.filter(
      x =>
        x.type === 'service' ||
        x.type === 'service-group'
    );

  const addressNames =
    new Set(
      addressObjects.map(x => x.name)
    );

  const serviceNames =
    new Set(
      serviceObjects.map(x => x.name)
    );
  for (const object of ctx.objects) {
    if (object.type === 'address-group') {
      for (const ref of object.members || []) {
        if (ref === object.name) {
          findings.push({
            severity: 'warn',
            rule: object.name,
            code: 'GROUP_CYCLE',
            text:
              `Address group ${object.name} references itself.`
          });
        } else if (
          !addressNames.has(ref) &&
          !looksLikeBuiltInAny(ref)
        ) {
          findings.push({
            severity: 'warn',
            rule: object.name,
            code: 'UNRESOLVED_ADDRESS_REFERENCE',
            text:
              `Address group ${object.name} references missing object ${ref}.`
          });
        }
      }
    }

    if (object.type === 'service-group') {
      for (const ref of object.members || []) {
        if (ref === object.name) {
          findings.push({
            severity: 'warn',
            rule: object.name,
            code: 'SERVICE_GROUP_CYCLE',
            text:
              `Service group ${object.name} references itself.`
          });
        } else if (
          !serviceNames.has(ref) &&
          !looksLikeBuiltInAny(ref)
        ) {
          findings.push({
            severity: 'warn',
            rule: object.name,
            code: 'UNRESOLVED_SERVICE_REFERENCE',
            text:
              `Service group ${object.name} references missing service ${ref}.`
          });
        }
      }
    }
  }

  /* Security rule references. */
  for (const rule of ctx.securityRules) {
    for (const ref of [
      ...(rule.sourceAddresses || []),
      ...(rule.destinationAddresses || [])
    ]) {
      if (
        !looksLikeBuiltInAny(ref) &&
        !addressNames.has(ref)
      ) {
        findings.push({
          severity: 'warn',
          rule: rule.name,
          code: 'UNRESOLVED_RULE_ADDRESS_REFERENCE',
          text:
            `Security rule ${rule.name} references ` +
            `address/group ${ref}, which is not in the parsed object inventory.`
        });
      }
    }

    for (const ref of rule.services || []) {
      if (
        !looksLikeBuiltInAny(ref) &&
        ref.toLowerCase() !== 'application-default' &&
        !serviceNames.has(ref)
      ) {
        findings.push({
          severity: 'warn',
          rule: rule.name,
          code: 'UNRESOLVED_RULE_SERVICE_REFERENCE',
          text:
            `Security rule ${rule.name} references service/group ${ref}, ` +
            `which is not in the parsed object inventory.`
        });
      }
    }
  }

  const devices =
    Object.values(
      ctx.configuration.devices || {}
    );

  const allVsysNames =
    new Set(
      devices.flatMap(
        device =>
          (device.vsys || []).map(
            vsys => vsys.name
          )
      )
    );

  for (const user of ctx.configuration.management.users || []) {
    for (const vsys of user.vsysAdmins || []) {
      if (
        vsys &&
        !allVsysNames.has(vsys)
      ) {
        findings.push({
          severity: 'warn',
          rule: user.name,
          code: 'UNRESOLVED_USER_VSYS_REFERENCE',
          text:
            `Management user ${user.name} references missing VSYS ${vsys}.`
        });
      }
    }
  }

  for (const device of devices) {
    const interfaceNames =
      new Set(
        (device.network.interfaces || [])
          .map(x => x.name)
      );

    const tunnelNames =
      new Set(
        (device.network.interfaces || [])
          .filter(
            x => x.type === 'tunnel'
          )
          .map(x => x.name)
      );

    const templateNames =
      new Set(
        (ctx.configuration.templates || [])
          .map(x => x.name)
      );

    for (const zone of device.network.zones || []) {
      for (const member of zone.members || []) {
        if (
          member &&
          !interfaceNames.has(member) &&
          !tunnelNames.has(member)
        ) {
          findings.push({
            severity: 'warn',
            rule: zone.name,
            code: 'UNRESOLVED_ZONE_MEMBER',
            text:
              `Zone ${zone.name} references ${member}, ` +
              `which is not in the interface/tunnel inventory.`
          });
        }
      }
    }

    for (const vr of device.network.virtualRouters || []) {
      for (const member of vr.interfaces || []) {
        if (
          member &&
          !interfaceNames.has(member)
        ) {
          findings.push({
            severity: 'warn',
            rule: vr.name,
            code: 'UNRESOLVED_VR_INTERFACE',
            text:
              `Virtual router ${vr.name} references interface ${member}, ` +
              `which is not in the interface inventory.`
          });
        }
      }
    }

    for (const vsys of device.vsys || []) {
      const profileGroupNames =
        new Set(
          (vsys.profileGroups || [])
            .map(x => x.name)
        );

      for (const rule of vsys.securityRules || []) {
        for (const group of rule.profileGroups || []) {
          if (
            group &&
            !profileGroupNames.has(group)
          ) {
            findings.push({
              severity: 'warn',
              rule: rule.name,
              code: 'UNRESOLVED_PROFILE_GROUP',
              text:
                `Security rule ${rule.name} references missing ` +
                `profile group ${group}.`
            });
          }
        }
      }

      for (const nat of vsys.natRules || []) {
        for (const ref of [
          ...(nat.sourceAddresses || []),
          ...(nat.destinationAddresses || [])
        ]) {
          if (
            ref &&
            !looksLikeBuiltInAny(ref) &&
            !addressNames.has(ref)
          ) {
            findings.push({
              severity: 'warn',
              rule: nat.name,
              code: 'UNRESOLVED_NAT_ADDRESS_REFERENCE',
              text:
                `NAT rule ${nat.name} references address/group ${ref}, ` +
                `which is not in the parsed object inventory.`
            });
          }
        }
      }

      for (const tunnel of vsys.globalProtect?.gateway || []) {
        for (const auth of findLeafValues(
          tunnel.properties,
          'authentication-profile'
        )) {
          if (
            auth &&
            !hasNamedRecord(
              vsys.authenticationProfiles,
              auth
            )
          ) {
            findings.push({
              severity: 'warn',
              rule: tunnel.name,
              code: 'UNRESOLVED_GP_AUTH_PROFILE',
              text:
                `GlobalProtect gateway ${tunnel.name} references ` +
                `authentication profile ${auth}, which is not defined in the VSYS.`
            });
          }
        }
      }
    }

    for (const stack of ctx.configuration.templateStacks || []) {
      for (const ref of findLeafValues(
        stack.properties,
        'member'
      )) {
        if (
          ref &&
          !templateNames.has(ref)
        ) {
          findings.push({
            severity: 'warn',
            rule: stack.name,
            code: 'UNRESOLVED_TEMPLATE_REFERENCE',
            text:
              `Template stack ${stack.name} references template ${ref}, ` +
              `which is not present in the parsed template inventory.`
          });
        }
      }
    }

    for (const tunnel of device.network.ike?.ipsecTunnels || []) {
      for (const ref of findLeafValues(
        tunnel.properties,
        'tunnel-interface'
      )) {
        if (
          ref &&
          !tunnelNames.has(ref)
        ) {
          findings.push({
            severity: 'warn',
            rule: tunnel.name,
            code: 'UNRESOLVED_IPSEC_TUNNEL_INTERFACE',
            text:
              `IPsec tunnel ${tunnel.name} references tunnel interface ${ref}, ` +
              `which is not in the parsed tunnel inventory.`
          });
        }
      }
    }
  }

  return findings;
}

function validateXmlConfiguration(ctx) {
  const findings = [];
  for (const object of ctx.objects) {
    if (object.type === 'address') {
      if (
        !object.ipNetmask &&
        !object.fqdn &&
        !object.value
      ) {
        findings.push({
          severity: 'warn',
          rule: object.name,
          code: 'EMPTY_ADDRESS_VALUE',
          text:
            `Address object ${object.name} has no IP/netmask or FQDN value.`
        });
      }

      if (
        object.ipNetmask &&
        !validIpOrCidr(object.ipNetmask)
      ) {
        findings.push({
          severity: 'warn',
          rule: object.name,
          code: 'INVALID_ADDRESS_VALUE',
          text:
            `Address object ${object.name} has invalid IP/CIDR value ` +
            `${object.ipNetmask}.`
        });
      }
    }

    if (object.type === 'service') {
      for (const protocol of object.protocols || []) {
        for (const port of protocol.ports || []) {
          if (!validPortExpression(port)) {
            findings.push({
              severity: 'warn',
              rule: object.name,
              code: 'INVALID_SERVICE_PORT',
              text:
                `Service ${object.name} has invalid ${protocol.protocol} ` +
                `port expression ${port}.`
            });
          }
        }
      }

      const protocols =
        new Set(
          (object.protocols || [])
            .map(x => x.protocol)
        );

      if (
        protocols.has('tcp') &&
        protocols.has('udp')
      ) {
        findings.push({
          severity: 'warn',
          rule: object.name,
          code: 'SERVICE_PROTOCOL_CONFLICT',
          text:
            `Service ${object.name} defines both TCP and UDP protocol branches.`
        });
      }
    }
  }

  for (const device of Object.values(
    ctx.configuration.devices || {}
  )) {
    for (const iface of device.network.interfaces || []) {
      const duplicateIps =
        duplicateValues(iface.ips || []);

      if (duplicateIps.length) {
        findings.push({
          severity: 'warn',
          rule: iface.name,
          code: 'DUPLICATE_INTERFACE_IP',
          text:
            `Interface ${iface.name} repeats IP/CIDR value(s): ` +
            duplicateIps.join(', ') + '.'
        });
      }

      for (const ip of iface.ips || []) {
        if (
          ip &&
          looksLikeIpOrCidr(ip) &&
          !validIpOrCidr(ip)
        ) {
          findings.push({
            severity: 'warn',
            rule: iface.name,
            code: 'INVALID_INTERFACE_IP',
            text:
              `Interface ${iface.name} contains invalid IP/CIDR value ${ip}.`
          });
        }
      }

      if (iface.tap) {
        findings.push({
          severity: 'info',
          rule: iface.name,
          code: 'TAP_INTERFACE',
          text:
            `Interface ${iface.name} is marked as a tap interface.`
        });
      }
    }

    for (const zone of device.network.zones || []) {
      const duplicateMembers =
        duplicateValues(
          zone.members || []
        );

      if (duplicateMembers.length) {
        findings.push({
          severity: 'warn',
          rule: zone.name,
          code: 'DUPLICATE_ZONE_MEMBER',
          text:
            `Zone ${zone.name} repeats member(s): ` +
            duplicateMembers.join(', ') + '.'
        });
      }

      if (!(zone.members || []).length) {
        findings.push({
          severity: 'info',
          rule: zone.name,
          code: 'EMPTY_ZONE',
          text:
            `Zone ${zone.name} has no interface or tunnel members.`
        });
      }
    }
    for (const vr of device.network.virtualRouters || []) {
      const duplicateInterfaces =
        duplicateValues(
          vr.interfaces || []
        );

      if (duplicateInterfaces.length) {
        findings.push({
          severity: 'warn',
          rule: vr.name,
          code: 'DUPLICATE_VR_INTERFACE',
          text:
            `Virtual router ${vr.name} repeats interface member(s): ` +
            duplicateInterfaces.join(', ') + '.'
        });
      }

      for (const asn of findLeafValues(
        vr.protocols?.bgp,
        'peer-as'
      ).concat(
        findLeafValues(
          vr.protocols?.bgp,
          'local-as'
        )
      )) {
        if (
          !/^\d+$/.test(String(asn)) ||
          Number(asn) > 4294967295
        ) {
          findings.push({
            severity: 'warn',
            rule: vr.name,
            code: 'INVALID_BGP_AS',
            text:
              `Virtual router ${vr.name} contains invalid BGP AS value ${asn}.`
          });
        }
      }

      const destinations = [];

      for (const route of vr.staticRoutes || []) {
        const destination =
          textAtProperties(
            route,
            ['destination']
          );

        if (destination) {
          destinations.push(destination);
        }

        const metric =
          numberValue(
            textAtProperties(
              route,
              ['metric']
            )
          );

        if (
          metric !== null &&
          metric < 0
        ) {
          findings.push({
            severity: 'warn',
            rule: vr.name,
            code: 'INVALID_ROUTE_METRIC',
            text:
              `Static route ${destination || '(unnamed)'} has negative metric ${metric}.`
          });
        }

        const adminDistance =
          numberValue(
            textAtProperties(
              route,
              ['admin-dist']
            )
          );

        if (
          adminDistance !== null &&
          (
            adminDistance < 0 ||
            adminDistance > 255
          )
        ) {
          findings.push({
            severity: 'warn',
            rule: vr.name,
            code: 'INVALID_ADMIN_DISTANCE',
            text:
              `Static route ${destination || '(unnamed)'} has unusual administrative distance ${adminDistance}.`
          });
        }
      }

      const duplicateDestinations =
        duplicateValues(destinations);

      if (duplicateDestinations.length) {
        findings.push({
          severity: 'warn',
          rule: vr.name,
          code: 'DUPLICATE_STATIC_ROUTE_DESTINATION',
          text:
            `Virtual router ${vr.name} has duplicate static-route destination(s): ` +
            duplicateDestinations.join(', ') + '.'
        });
      }
    }

    /* DHCP. */
    for (const dhcp of device.network.dhcp || []) {
      const pools =
        valuesAtProperties(
          dhcp.properties,
          ['ip-pool', 'member']
        );

      const parsedPools = [];

      for (const pool of pools) {
        const [startIp, endIp] =
          String(pool).split('-');

        if (
          validIp(startIp) &&
          validIp(endIp)
        ) {
          const start =
            ipToInt(startIp);

          const end =
            ipToInt(endIp);

          parsedPools.push({
            raw: pool,
            start,
            end
          });

          if (start > end) {
            findings.push({
              severity: 'warn',
              rule: dhcp.name,
              code: 'INVALID_DHCP_RANGE',
              text:
                `DHCP pool ${pool} starts after it ends.`
            });
          }
        }
      }

      for (let i = 0; i < parsedPools.length; i++) {
        for (let j = i + 1; j < parsedPools.length; j++) {
          const a = parsedPools[i];
          const b = parsedPools[j];

          if (
            a.start <= b.end &&
            b.start <= a.end
          ) {
            findings.push({
              severity: 'warn',
              rule: dhcp.name,
              code: 'OVERLAPPING_DHCP_POOLS',
              text:
                `DHCP pools ${a.raw} and ${b.raw} overlap.`
            });
          }
        }
      }

      const lease =
        numberValue(
          textAtProperties(
            dhcp.properties,
            ['lease']
          )
        );

      if (
        lease !== null &&
        lease < 0
      ) {
        findings.push({
          severity: 'warn',
          rule: dhcp.name,
          code: 'INVALID_DHCP_LEASE',
          text:
            `DHCP server ${dhcp.name} has negative lease value ${lease}.`
        });
      }
    }
    for (const vsys of device.vsys || []) {
      for (const rule of vsys.natRules || []) {
        const hasStatic =
          findLeafValues(
            rule.properties,
            'static-ip'
          ).length > 0;

        const hasDynamic =
          findLeafValues(
            rule.properties,
            'dynamic-ip-and-port'
          ).length > 0;

        if (
          hasStatic &&
          hasDynamic
        ) {
          findings.push({
            severity: 'warn',
            rule: rule.name,
            code: 'NAT_TRANSLATION_CONFLICT',
            text:
              `NAT rule ${rule.name} contains both static and dynamic ` +
              `source-translation branches.`
          });
        }
      }

      for (const rule of vsys.qosRules || []) {
        const qosClass = rule.class;

        if (
          qosClass !== null &&
          (
            !Number.isInteger(qosClass) ||
            qosClass < 1
          )
        ) {
          findings.push({
            severity: 'warn',
            rule: rule.name,
            code: 'INVALID_QOS_CLASS',
            text:
              `QoS rule ${rule.name} has invalid class ${qosClass}.`
          });
        }

        const kbps =
          numberValue(
            textAtProperties(
              rule.actionDetails,
              ['guaranteed-kbps']
            )
          );

        if (
          kbps !== null &&
          kbps < 0
        ) {
          findings.push({
            severity: 'warn',
            rule: rule.name,
            code: 'INVALID_QOS_RATE',
            text:
              `QoS rule ${rule.name} has negative guaranteed-kbps ${kbps}.`
          });
        }
      }

      for (const rule of vsys.applicationOverrideRules || []) {
        if (
          rule.port &&
          !validPortExpression(
            rule.port
          )
        ) {
          findings.push({
            severity: 'warn',
            rule: rule.name,
            code: 'INVALID_OVERRIDE_PORT',
            text:
              `Application-override rule ${rule.name} has invalid port ${rule.port}.`
          });
        }
      }

      for (const rule of vsys.decryptionRules || []) {
        const types =
          findLeafValues(
            rule.actionDetails,
            'type'
          );

        for (const type of types) {
          if (
            /unknown-/i.test(type)
          ) {
            findings.push({
              severity: 'warn',
              rule: rule.name,
              code: 'UNKNOWN_DECRYPTION_TYPE',
              text:
                `Decryption rule ${rule.name} contains unrecognized decryption type ${type}.`
            });
          }
        }
      }

      /* Profiles. */
      for (const profileList of Object.values(
        vsys.profiles || {}
      )) {
        for (const profile of profileList || []) {
          const blockValues =
            findLeafValues(
              profile.properties,
              'block'
            );

          const allowValues =
            findLeafValues(
              profile.properties,
              'allow'
            );

          if (
            blockValues.includes('any') &&
            allowValues.includes('any')
          ) {
            findings.push({
              severity: 'warn',
              rule: profile.name,
              code: 'PROFILE_BLOCK_ALLOW_CONTRADICTION',
              text:
                `Profile ${profile.name} contains both block=any and allow=any.`
            });
          }

          if (
            profile.type === 'fileblocking' ||
            profile.type === 'fileBlocking' ||
            profile.type === 'datafiltering' ||
            profile.type === 'dataFiltering'
          ) {
            for (const childRule of xmlRecordEntries(
              profile.properties,
              'rules'
            )) {
              if (
                !findLeafValues(
                  childRule,
                  'action'
                ).length
              ) {
                findings.push({
                  severity: 'warn',
                  rule: profile.name,
                  code: 'PROFILE_RULE_MISSING_ACTION',
                  text:
                    `Profile ${profile.name} contains a nested rule without an action value.`
                });
              }
            }
          }
        }
      }
      for (const cert of vsys.certificates || []) {
        if (
          cert.notAfter &&
          !validTimestamp(
            cert.notAfter
          )
        ) {
          findings.push({
            severity: 'warn',
            rule: cert.name,
            code: 'INVALID_CERTIFICATE_DATE',
            text:
              `Certificate ${cert.name} contains invalid not-after value ${cert.notAfter}.`
          });
        } else if (
          cert.notAfter &&
          new Date(cert.notAfter).getTime() <
            Date.now()
        ) {
          findings.push({
            severity: 'warn',
            rule: cert.name,
            code: 'EXPIRED_CERTIFICATE',
            text:
              `Certificate ${cert.name} has expired.`
          });
        }
      }

      for (const schedule of vsys.schedules || []) {
        for (const time of findLeafValues(
          schedule.properties,
          'start'
        ).concat(
          findLeafValues(
            schedule.properties,
            'end'
          )
        )) {
          if (
            !validClockTime(time)
          ) {
            findings.push({
              severity: 'warn',
              rule: schedule.name,
              code: 'INVALID_SCHEDULE_TIME',
              text:
                `Schedule ${schedule.name} contains invalid time ${time}.`
            });
          }
        }
      }
    }
  }
  const pc =
    ctx.configuration.management.passwordComplexity;

  if (
    pc &&
    Number(
      textAtProperties(
        pc,
        ['password-history-count']
      )
    ) < 0
  ) {
    findings.push({
      severity: 'warn',
      rule: '/config/mgt-config/password-complexity',
      code: 'PASSWORD_HISTORY_RANGE',
      text:
        'Password history count is negative.'
    });
  }

  for (const item of ctx.inventory) {
    if (
      item.kind !== 'element' ||
      !item.isLeaf
    ) {
      continue;
    }

    const name =
      String(item.name || '')
        .toLowerCase();

    const value =
      String(item.value || '')
        .trim();

    if (
      (name === 'date' ||
       name === 'date-only') &&
      value &&
      !validDateOnly(value)
    ) {
      findings.push({
        severity: 'warn',
        rule: item.path,
        code: 'INVALID_DATE_ONLY',
        text:
          `Date-like XML value ${value} is not a valid calendar date.`
      });
    }

    if (
      /^timestamp(?:-|$)/i.test(name) &&
      value &&
      !validTimestamp(
        value.replace(' ', 'T')
      )
    ) {
      findings.push({
        severity: 'warn',
        rule: item.path,
        code: 'INVALID_XML_TIMESTAMP',
        text:
          `Timestamp-like XML value ${value} could not be parsed as a timestamp.`
      });
    }
  }

  for (const audit of ctx.configuration.state.audit || []) {
    const timestamp =
      audit.attributes?.timestamp;

    if (
      timestamp &&
      !validTimestamp(timestamp)
    ) {
      findings.push({
        severity: 'warn',
        rule: audit.name,
        code: 'INVALID_AUDIT_TIMESTAMP',
        text:
          `Audit entry contains invalid timestamp ${timestamp}.`
      });
    }

    const result =
      audit.attributes?.result;

    if (
      result &&
      ![
        'success',
        'failure',
        'unknown'
      ].includes(
        String(result).toLowerCase()
      )
    ) {
      findings.push({
        severity: 'warn',
        rule: audit.name,
        code: 'INVALID_AUDIT_RESULT',
        text:
          `Audit entry contains unrecognized result value ${result}.`
      });
    }
  }

  for (const device of Object.values(
    ctx.configuration.devices || {}
  )) {
    for (const plugin of device.plugins || []) {
      const enabled =
        findLeafValues(
          plugin.properties,
          'enabled'
        )[0];

      if (
        enabled &&
        !/^(yes|no|true|false)$/i.test(
          enabled
        )
      ) {
        findings.push({
          severity: 'warn',
          rule: plugin.name,
          code: 'INVALID_PLUGIN_BOOLEAN',
          text:
            `Plugin ${plugin.name} has unrecognized enabled value ${enabled}.`
        });
      }
    }
  }

  return findings;
}

function analyzeXmlConfiguration(parsed) {
  const findings = [
    ...(parsed.findings || [])
  ];

  findings.push(
    ...analyzeRules(
      parsed.securityRules
    )
  );

  findings.push(
    ...analyzeSemanticRuleOverlap(
      parsed.securityRules
    )
  );

  findings.push(
    ...analyzeSecurityRuleMetadata(
      parsed.securityRules
    )
  );

  if (
    parsed.coverage?.unrecognizedMajorSections?.length
  ) {
    for (const section of parsed.coverage.unrecognizedMajorSections) {
      findings.push({
        severity: 'info',
        rule: section,
        code: 'UNRECOGNIZED_MAJOR_SECTION',
        text:
          `Root XML section ${section} has no dedicated semantic parser. ` +
          `Its contents remain available in the complete XML inventory.`
      });
    }
  }

  return dedupeFindings(findings);
}

function analyzeSemanticRuleOverlap(rules) {
  const findings = [];

  for (let i = 0; i < rules.length; i++) {
    const earlier = rules[i];

    if (earlier.disabled) continue;

    for (let j = i + 1; j < rules.length; j++) {
      const later = rules[j];

      if (later.disabled) continue;

      if (
        sameMatchScope(
          earlier,
          later
        )
      ) {
        continue;
      }

      if (
        !ruleScopeContains(
          earlier,
          later
        )
      ) {
        continue;
      }

      const earlierAction =
        String(
          earlier.action || ''
        ).toLowerCase();

      const laterAction =
        String(
          later.action || ''
        ).toLowerCase();

      if (
        /^(deny|drop|reject)$/.test(
          earlierAction
        ) &&
        /^(allow|permit)$/.test(
          laterAction
        )
      ) {
        findings.push({
          severity: 'warn',
          rule: later.name,
          code: 'POTENTIAL_SEMANTIC_SHADOW',
          text:
            `Later rule "${later.name}" is contained by the earlier scope ` +
            `of "${earlier.name}", which denies traffic. Review whether ` +
            `the later allow can ever be reached.`
        });
      } else if (
        earlierAction !== laterAction
      ) {
        findings.push({
          severity: 'warn',
          rule: later.name,
          code: 'OVERLAPPING_CONFLICT',
          text:
            `Rule "${later.name}" is contained by the earlier scope ` +
            `of "${earlier.name}", but the actions differ ` +
            `(${earlier.action} vs ${later.action}).`
        });
      } else {
        findings.push({
          severity: 'info',
          rule: later.name,
          code: 'OVERLAPPING_SCOPE',
          text:
            `Rule "${later.name}" is contained by the earlier scope ` +
            `of "${earlier.name}". Review whether the overlap is intentional.`
        });
      }
    }
  }

  return findings;
}

function analyzeSecurityRuleMetadata(rules) {
  const findings = [];

  for (const rule of rules) {
    if (
      !rule.name ||
      rule.name === '(unnamed)'
    ) {
      findings.push({
        severity: 'warn',
        rule: rule.name,
        code: 'MISSING_RULE_NAME',
        text:
          'Security rule has no usable name.'
      });
    }

    if (
      rule.action === 'unknown'
    ) {
      findings.push({
        severity: 'warn',
        rule: rule.name,
        code: 'EMPTY_ACTION',
        text:
          'Security rule has no action value.'
      });
    } else if (
      !/^(allow|permit|deny|drop|reject)$/i.test(
        rule.action
      )
    ) {
      findings.push({
        severity: 'warn',
        rule: rule.name,
        code: 'UNKNOWN_ACTION',
        text:
          `Security rule action "${rule.action}" is not in the known allow/deny set.`
      });
    }
  }

  return findings;
}

function sameMatchScope(a, b) {
  const fields = [
    'from',
    'to',
    'sourceAddresses',
    'destinationAddresses',
    'applications',
    'services',
    'categories',
    'users'
  ];

  return fields.every(
    key =>
      setEqual(
        a[key],
        b[key]
      )
  );
}

function ruleScopeContains(broad, narrow) {
  if (
    broad.negateSource ||
    broad.negateDestination ||
    narrow.negateSource ||
    narrow.negateDestination
  ) {
    return false;
  }

  const fields = [
    'from',
    'to',
    'sourceAddresses',
    'destinationAddresses',
    'applications',
    'services',
    'categories',
    'users'
  ];

  return fields.every(
    key =>
      matchFieldContains(
        broad[key],
        narrow[key]
      )
  );
}

function matchFieldContains(broad, narrow) {
  const b =
    normalizeMatchField(broad);

  const n =
    normalizeMatchField(narrow);

  if (b.any) return true;

  if (n.any) return false;

  for (const value of n.values) {
    if (!b.values.has(value)) {
      return false;
    }
  }

  return true;
}

function normalizeMatchField(values) {
  const normalized =
    (values || [])
      .map(
        value =>
          String(value)
            .trim()
            .toLowerCase()
      )
      .filter(Boolean);

  return {
    any:
      normalized.length === 0 ||
      normalized.some(
        x =>
          x === 'any' ||
          x === 'all' ||
          x === '*'
      ),

    values:
      new Set(normalized)
  };
}
function buildXmlCoverage(ctx) {
  const rootNames =
    elementChildren(ctx.root)
      .map(localName);

  const knownRootSections = [
    'mgt-config',
    'shared',
    'devices',
    'readonly',
    'config-locks',
    'audit'
  ];

  return {
    totalElements:
      ctx.inventory.filter(
        x => x.kind === 'element'
      ).length,

    leafElements:
      ctx.inventory.filter(
        x =>
          x.kind === 'element' &&
          x.isLeaf
      ).length,

    attributeCount:
      ctx.inventory.filter(
        x => x.kind === 'attribute'
      ).length,

    commentCount:
      ctx.inventory.filter(
        x => x.kind === 'comment'
      ).length,

    recognizedMajorSections:
      knownRootSections.filter(
        x => rootNames.includes(x)
      ),

    unrecognizedMajorSections:
      unique(
        rootNames.filter(
          x =>
            !knownRootSections.includes(x)
        )
      ),

    guarantee:
      'Every XML element, attribute and comment is retained in the browser-side inventory.'
  };
}

function buildXmlInventory(root) {
  const rows = [];

  walkXmlNodes(
    root,
    (node, parent) => {
      if (node.nodeType === 1) {
        const children =
          elementChildren(node);

        rows.push({
          kind: 'element',
          path: xmlPath(node),
          name: localName(node),
          isLeaf:
            children.length === 0,
          value:
            directText(node),
          attributes:
            attributesOf(node)
        });

        for (const attribute of Array.from(
          node.attributes || []
        )) {
          rows.push({
            kind: 'attribute',
            path:
              `${xmlPath(node)}/@${attribute.name}`,
            name:
              `@${attribute.name}`,
            isLeaf: true,
            value:
              attribute.value,
            attributes: {}
          });
        }
      }

      if (node.nodeType === 8) {
        rows.push({
          kind: 'comment',
          path:
            `${xmlPath(parent || root)}/#comment`,
          name: '#comment',
          isLeaf: true,
          value:
            node.nodeValue || '',
          attributes: {}
        });
      }

      if (node.nodeType === 7) {
        rows.push({
          kind: 'processing-instruction',
          path:
            `${xmlPath(parent || root)}/#pi`,
          name:
            node.target || '#pi',
          isLeaf: true,
          value:
            node.nodeValue || '',
          attributes: {}
        });
      }
    }
  );

  return rows;
}

function flattenXml(node) {
  if (!node) return null;

  const result = {
    tag: localName(node),
    attributes:
      attributesOf(node),
    children: {}
  };

  for (const child of elementChildren(node)) {
    const key =
      localName(child);

    const value =
      elementChildren(child).length
        ? flattenXml(child)
        : directText(child);

    if (
      Object.prototype.hasOwnProperty.call(
        result.children,
        key
      )
    ) {
      if (
        !Array.isArray(
          result.children[key]
        )
      ) {
        result.children[key] = [
          result.children[key]
        ];
      }

      result.children[key].push(value);
    } else {
      result.children[key] = value;
    }
  }

  return result;
}

function walkXmlNodes(
  node,
  callback,
  parent = null
) {
  if (!node) return;

  callback(node, parent);

  for (const child of Array.from(
    node.childNodes || []
  )) {
    walkXmlNodes(
      child,
      callback,
      node
    );
  }
}

function walkElements(node, callback) {
  if (!node || node.nodeType !== 1) return;

  callback(node);

  for (const child of elementChildren(node)) {
    walkElements(
      child,
      callback
    );
  }
}

function elementChildren(node) {
  return node
    ? Array.from(node.children || [])
    : [];
}

function childEntries(node) {
  return elementChildren(node)
    .filter(
      node =>
        localName(node) === 'entry'
    );
}

function parseNamedEntries(
  node,
  type,
  mapper
) {
  if (!node) return [];

  return childEntries(node)
    .map(mapper);
}

function localName(node) {
  return String(
    node?.localName ||
    node?.tagName ||
    ''
  )
    .split(':')
    .pop()
    .toLowerCase();
}

function xmlPath(node) {
  const parts = [];

  let current = node;

  while (
    current &&
    current.nodeType === 1
  ) {
    const name =
      localName(current);

    const parent =
      current.parentElement;

    const siblings =
      parent
        ? elementChildren(parent)
            .filter(
              x =>
                localName(x) ===
                name
            )
        : [];

    const index =
      siblings.indexOf(current);

    parts.unshift(
      siblings.length > 1 &&
      index >= 0
        ? `${name}[${index + 1}]`
        : name
    );

    current = parent;
  }

  return '/' + parts.join('/');
}

function firstPath(root, parts) {
  let node = root;

  for (const part of parts) {
    node =
      elementChildren(node)
        .find(
          x =>
            localName(x) ===
            String(part).toLowerCase()
        );

    if (!node) return null;
  }

  return node;
}

function firstTextAt(root, paths) {
  for (const path of paths) {
    const node =
      firstPath(root, path);

    if (!node) continue;

    const text =
      directText(node);

    if (text) return text;
  }

  return '';
}

function textAt(root, path) {
  const node =
    firstPath(root, path);

  return node
    ? directText(node)
    : '';
}

function valuesAt(root, path) {
  if (!root || !path.length) {
    return [];
  }

  const parent =
    firstPath(
      root,
      path.slice(0, -1)
    );

  if (!parent) return [];

  const wanted =
    String(
      path[path.length - 1]
    ).toLowerCase();

  return elementChildren(parent)
    .filter(
      child =>
        localName(child) ===
        wanted
    )
    .map(
      child =>
        directText(child) ||
        String(
          child.textContent || ''
        ).trim()
    )
    .filter(Boolean);
}

function entryNamesAt(root, path) {
  const parent =
    firstPath(root, path);

  if (!parent) return [];

  return childEntries(parent)
    .map(
      entry =>
        attr(entry, 'name') ||
        directText(entry)
    )
    .filter(Boolean);
}

function hasPath(root, path) {
  return Boolean(
    firstPath(root, path)
  );
}

function attr(node, name) {
  return node?.getAttribute?.(name) || '';
}

function attributesOf(node) {
  const result = {};

  for (const attribute of Array.from(
    node?.attributes || []
  )) {
    result[attribute.name] =
      attribute.value;
  }

  return result;
}

function directText(node) {
  if (!node) return '';

  return Array.from(
    node.childNodes || []
  )
    .filter(
      n =>
        n.nodeType === 3 ||
        n.nodeType === 4
    )
    .map(
      n =>
        n.nodeValue || ''
    )
    .join('')
    .trim();
}

function recordEntry(
  node,
  type,
  extra = {}
) {
  return {
    name:
      attr(node, 'name') ||
      '(unnamed)',

    type,

    path:
      xmlPath(node),

    attributes:
      attributesOf(node),

    properties:
      flattenXml(node),

    ...extra
  };
}

function findLeafValues(
  object,
  leafName
) {
  const result = [];

  function visit(value, key = '') {
    if (
      value === null ||
      value === undefined
    ) {
      return;
    }

    if (
      typeof value ===
      'string'
    ) {
      if (
        key === leafName
      ) {
        result.push(value);
      }
      return;
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        visit(item, key);
      }
      return;
    }

    if (
      typeof value ===
      'object'
    ) {
      if (value.children) {
        for (const [
          childKey,
          childValue
        ] of Object.entries(
          value.children
        )) {
          visit(
            childValue,
            childKey
          );
        }
      }
    }
  }

  visit(object);

  return result;
}

function valuesAtProperties(
  object,
  path
) {
  if (!object) return [];

  let value = object;

  for (const part of path) {
    if (
      value &&
      typeof value === 'object' &&
      value.children
    ) {
      value =
        value.children[part];
    } else {
      return [];
    }
  }

  const values =
    Array.isArray(value)
      ? value
      : [value];

  return values
    .map(
      item =>
        typeof item ===
        'string'
          ? item
          : item?.text ||
            ''
    )
    .filter(Boolean);
}

function textAtProperties(
  object,
  path
) {
  const values =
    valuesAtProperties(
      object,
      path
    );

  return values[0] || '';
}

function xmlRecordEntries(
  properties,
  containerName
) {
  const container =
    properties?.children?.[
      containerName
    ];

  if (!container) return [];

  const entry =
    container?.children?.entry;

  if (!entry) return [];

  return Array.isArray(entry)
    ? entry
    : [entry];
}

function hasNamedRecord(
  records,
  name
) {
  return Boolean(
    (records || [])
      .some(
        x =>
          x.name === name
      )
  );
}

function parseServiceProtocols(
  node
) {
  const protocol =
    firstPath(
      node,
      ['protocol']
    );

  if (!protocol) return [];
  return elementChildren(
    protocol
  ).map(
    child => ({
      protocol:
        localName(child),

      ports:
        descendantsNamed(
          child,
          'port'
        )
          .map(
            port =>
              directText(port)
          )
          .filter(Boolean),

      properties:
        flattenXml(child)
    })
  );
}

function descendantsNamed(
  root,
  wanted
) {
  const result = [];

  walkElements(
    root,
    node => {
      if (
        node !== root &&
        localName(node) ===
          wanted
      ) {
        result.push(node);
      }
    }
  );
  return result;
}

function parseBoolean(
  value,
  fallback = false
) {
  if (value === '') {
    return fallback;
  }

  if (
    /^(yes|true|1|on)$/i.test(
      value
    )
  ) {
    return true;
  }

  if (
    /^(no|false|0|off)$/i.test(
      value
    )
  ) {
    return false;
  }

  return fallback;
}

function numberValue(value) {
  if (
    value === '' ||
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const n = Number(value);

  return Number.isFinite(n)
    ? n
    : null;
}

function validIpOrCidr(value) {
  const s =
    String(value || '')
      .trim();

  if (!s) return false;

  const parts =
    s.split('/');

  const ip =
    parts[0];

  if (!validIp(ip)) {
    return false;
  }

  if (parts.length === 1) {
    return true;
  }

  if (
    parts.length !== 2 ||
    !/^\d+$/.test(parts[1])
  ) {
    return false;
  }

  const prefix =
    Number(parts[1]);

  return ip.includes(':')
    ? prefix <= 128
    : prefix <= 32;
}

function validIp(value) {
  const s =
    String(value || '')
      .trim();

  if (
    /^\d+(?:\.\d+){3}$/.test(s)
  ) {
    return s
      .split('.')
      .every(
        octet =>
          Number(octet) >= 0 &&
          Number(octet) <= 255
      );
  }

  if (s.includes(':')) {
    return validIpv6(s);
  }

  return false;
}

function validIpv6(value) {
  const s =
    String(value || '')
      .toLowerCase();

  if (
    !/^[0-9a-f:]+$/.test(s)
  ) {
    return false;
  }

  if (
    s.includes(':::')
  ) {
    return false;
  }

  const halves =
    s.split('::');

  if (
    halves.length > 2
  ) {
    return false;
  }

  const left =
    halves[0]
      ? halves[0]
          .split(':')
          .filter(Boolean)
      : [];

  const right =
    halves.length === 2 &&
    halves[1]
      ? halves[1]
          .split(':')
          .filter(Boolean)
      : [];

  if (
    left.some(
      x => x.length > 4
    ) ||
    right.some(
      x => x.length > 4
    )
  ) {
    return false;
  }

  if (
    halves.length === 2
  ) {
    return (
      left.length +
        right.length <
      8
    );
  }

  return (
    left.length === 8
  );
}

function looksLikeIpOrCidr(
  value
) {
  return /[.:]/.test(
    String(value || '')
  );
}

function validPortExpression(
  value
) {
  const s =
    String(value || '')
      .trim();

  const match =
    s.match(
      /^(\d+)(?:-(\d+))?$/
    );

  if (!match) {
    return false;
  }

  const start =
    Number(match[1]);

  const end =
    match[2] === undefined
      ? start
      : Number(match[2]);

  return (
    start >= 1 &&
    start <= 65535 &&
    end >= 1 &&
    end <= 65535 &&
    start <= end
  );
}

function validTimestamp(value) {
  const s =
    String(value || '')
      .trim();

  if (!s) return false;

  const date =
    new Date(s);

  return Number.isFinite(
    date.getTime()
  );
}

function validDateOnly(value) {
  const match =
    String(value || '')
      .match(
        /^(\d{4})-(\d{2})-(\d{2})$/
      );

  if (!match) {
    return false;
  }

  const date =
    new Date(
      `${value}T00:00:00Z`
    );

  return (
    date.getUTCFullYear() ===
      Number(match[1]) &&
    date.getUTCMonth() + 1 ===
      Number(match[2]) &&
    date.getUTCDate() ===
      Number(match[3])
  );
}

function validClockTime(
  value
) {
  const match =
    String(value || '')
      .match(
        /^(\d{2}):(\d{2})$/
      );

  if (!match) return false;

  const hours =
    Number(match[1]);

  const minutes =
    Number(match[2]);

  return (
    hours >= 0 &&
    hours <= 23 &&
    minutes >= 0 &&
    minutes <= 59
  );
}

function ipToInt(value) {
  const octets =
    String(value || '')
      .split('.')
      .map(Number);

  if (
    octets.length !== 4 ||
    octets.some(
      n =>
        !Number.isInteger(n) ||
        n < 0 ||
        n > 255
    )
  ) {
    return NaN;
  }

  return (
    (
      (
        octets[0] * 256 +
        octets[1]
      ) * 256 +
      octets[2]
    ) * 256 +
    octets[3]
  );
}

function duplicateValues(
  values
) {
  const seen =
    new Set();

  const duplicates = [];

  for (const value of values || []) {
    if (seen.has(value)) {
      duplicates.push(value);
    }

    seen.add(value);
  }

  return unique(duplicates);
}

function unique(values) {
  return [
    ...new Set(values)
  ];
}

function looksLikeBuiltInAny(
  value
) {
  return [
    'any',
    'all',
    '*'
  ].includes(
    String(value || '')
      .trim()
      .toLowerCase()
  );
}

function dedupeFindings(
  findings
) {
  const seen =
    new Set();

  return findings.filter(
    finding => {
      const key =
        [
          finding.severity,
          finding.code,
          finding.rule,
          finding.text
        ].join('|');

      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    }
  );
}

function buildXmlStats(
  parsed,
  findings
) {
  const rules =
    parsed.securityRules || [];

  return {
    totalRules:
      rules.length,

    enabledRules:
      rules.filter(
        rule => !rule.disabled
      ).length,

    disabledRules:
      rules.filter(
        rule => rule.disabled
      ).length,

    allowRules:
      rules.filter(
        rule =>
          /^(allow|permit)$/i.test(
            rule.action
          )
      ).length,

    denyRules:
      rules.filter(
        rule =>
          /^(deny|drop|reject)$/i.test(
            rule.action
          )
      ).length,

    unknownActions:
      rules.filter(
        rule =>
          !/^(allow|permit|deny|drop|reject)$/i.test(
            rule.action
          )
      ).length,

    warnings:
      findings.filter(
        x =>
          x.severity === 'warn'
      ).length,

    info:
      findings.filter(
        x =>
          x.severity === 'info'
      ).length,

    objects:
      parsed.objects.length,

    interfaces:
      parsed.interfaces.length,

    zones:
      parsed.zones.length,

    xmlElements:
      parsed.coverage.totalElements,

    xmlLeaves:
      parsed.coverage.leafElements,

    xmlAttributes:
      parsed.coverage.attributeCount,

    xmlComments:
      parsed.coverage.commentCount
  };
}

function renderAnalysis(a) {
  const s =
    a.stats || {};

  const overall =
    s.warnings
      ? `
        <div class="status warning">
          <strong>${escapeHtml(String(s.warnings))} review item(s) found</strong><br>
          Local heuristics and validation identified configuration constructs
          that deserve review. This is not a PAN-OS commit simulator.
        </div>
      `
      : `
        <div class="status success">
          <strong>No heuristic warning was detected.</strong><br>
          This does not prove that the configuration is secure or operationally correct.
        </div>
      `;

  const statCards = [
    ['Rules', s.totalRules],
    ['Enabled', s.enabledRules],
    ['Disabled', s.disabledRules],
    ['Allow', s.allowRules],
    ['Deny', s.denyRules],
    ['Warnings', s.warnings],
    ['Objects', s.objects],
    ['Interfaces', s.interfaces],
    ['Zones', s.zones],
    ['XML elements', s.xmlElements],
    ['XML leaves', s.xmlLeaves],
    ['XML attributes', s.xmlAttributes]
  ]
    .map(
      ([label, value]) =>
        `
        <div class="stat">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(String(value ?? 0))}</strong>
        </div>
        `
    )
    .join('');

  const findings =
    renderFindings(
      a.findings || []
    );

  const rules =
    renderSecurityRules(
      a.rules || []
    );

  if (a.format !== 'xml') {
    return `
      ${overall}
      <h3>Configuration overview</h3>
      <div class="grid">${statCards}</div>
      <p class="small">
        Detected format:
        <strong>${escapeHtml(
          String(a.format || '').toUpperCase()
        )}</strong>
        ${
          a.metadata?.hostname
            ? ` · Hostname: <strong>${escapeHtml(a.metadata.hostname)}</strong>`
            : ''
        }
      </p>

      <h3>Rule analysis</h3>
      ${findings}

      <h3>Effective rule view</h3>
      ${rules}

      <h3>Objects</h3>
      ${renderObjects(a.objects || [])}

      <h3>Interfaces</h3>
      ${renderSimpleRecords(a.interfaces || [])}
    `;
  }

  return `
    ${overall}

    <h3>Configuration overview</h3>
    <div class="grid">${statCards}</div>

    <p class="small">
      Detected format:
      <strong>XML</strong>
      ${
        a.metadata?.hostname
          ? ` · Hostname: <strong>${escapeHtml(a.metadata.hostname)}</strong>`
          : ''
      }
      ${
        a.metadata?.panOsVersion
          ? ` · PAN-OS: <strong>${escapeHtml(a.metadata.panOsVersion)}</strong>`
          : ''
      }
      ${
        a.metadata?.serial
          ? ` · Serial: <strong>${escapeHtml(a.metadata.serial)}</strong>`
          : ''
      }
      ${
        a.metadata?.configVersion
          ? ` · Config version: <strong>${escapeHtml(a.metadata.configVersion)}</strong>`
          : ''
      }
    </p>

    <h3>Findings</h3>
    ${findings}

    <h3>Security policy</h3>
    ${rules}

    <h3>Objects</h3>
    ${renderObjects(a.objects || [])}

    <h3>Shared configuration</h3>
    ${renderSharedConfiguration(
      a.configuration?.shared
    )}

    <h3>Network and routing</h3>
    ${renderNetworkConfiguration(
      a.configuration?.devices || {}
    )}

    <h3>Other policy rulebases</h3>
    ${renderPolicyRulebases(
      a.configuration?.devices || {}
    )}

    <h3>Profiles, authentication and remote access</h3>
    ${renderProfilesConfiguration(
      a.configuration?.devices || {}
    )}

    <h3>Management and configuration state</h3>
    ${renderManagementState(
      a.configuration
    )}

    <h3>Parser coverage</h3>
    ${renderCoverage(
      a.coverage
    )}

    <h3>Complete XML inventory</h3>
    <p class="small">
      This table is the loss-resistant fallback. Every XML element,
      attribute, comment and processing instruction is retained here,
      including content that has no dedicated semantic parser yet.
      Sensitive fields are redacted in the visible view.
    </p>
    ${renderXmlInventory(
      a.inventory || []
    )}
  `;
}

function renderFindings(
  findings
) {
  if (!findings.length) {
    return `
      <div class="status success">
        No heuristic or validation findings.
      </div>
    `;
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule / Object</th>
            <th>Code</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          ${findings
            .map(
              finding =>
                `
                <tr>
                  <td>
                    <strong>
                      ${escapeHtml(
                        String(
                          finding.severity ||
                          ''
                        ).toUpperCase()
                      )}
                    </strong>
                  </td>
                  <td>
                    ${escapeHtml(
                      finding.rule || ''
                    )}
                  </td>
                  <td>
                    <code>
                      ${escapeHtml(
                        finding.code || ''
                      )}
                    </code>
                  </td>
                  <td>
                    ${escapeHtml(
                      finding.text || ''
                    )}
                  </td>
                </tr>
                `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderSecurityRules(
  rules
) {
  if (!rules.length) {
    return `
      <div class="status warning">
        No security rules were recognized.
      </div>
    `;
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Scope</th>
            <th>Rule</th>
            <th>From</th>
            <th>To</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Application</th>
            <th>Service</th>
            <th>Category</th>
            <th>User</th>
            <th>Action</th>
            <th>Profiles</th>
          </tr>
        </thead>
        <tbody>
          ${rules
            .map(
              (rule, index) =>
                `
                <tr>
                  <td>${index + 1}</td>
                  <td>${escapeHtml(
                    rule.scope || ''
                  )}</td>
                  <td>
                    <strong>
                      ${escapeHtml(rule.name)}
                    </strong>
                    ${
                      rule.disabled
                        ? '<br><span class="small">disabled</span>'
                        : ''
                    }
                    ${
                      rule.uuid
                        ? `<br><span class="small">UUID: ${escapeHtml(rule.uuid)}</span>`
                        : ''
                    }
                  </td>
                  <td>${renderList(
                    rule.from
                  )}</td>
                  <td>${renderList(
                    rule.to
                  )}</td>
                  <td>${renderList(
                    rule.sourceAddresses
                  )}</td>
                  <td>${renderList(
                    rule.destinationAddresses
                  )}</td>
                  <td>${renderList(
                    rule.applications
                  )}</td>
                  <td>${renderList(
                    rule.services
                  )}</td>
                  <td>${renderList(
                    rule.categories
                  )}</td>
                  <td>${renderList(
                    rule.users
                  )}</td>
                  <td>
                    <strong>
                      ${escapeHtml(
                        rule.action || ''
                      )}
                    </strong>
                  </td>
                  <td>${renderList(
                    rule.profileGroups
                  )}</td>
                </tr>
                `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderObjects(
  objects
) {
  if (!objects.length) {
    return `
      <p class="small">
        No semantic objects were recognized.
      </p>
    `;
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Scope</th>
            <th>Name</th>
            <th>Type</th>
            <th>Value / Members</th>
            <th>Path</th>
          </tr>
        </thead>
        <tbody>
          ${objects
            .map(
              object =>
                `
                <tr>
                  <td>${escapeHtml(
                    object.scope || 'shared'
                  )}</td>
                  <td>${escapeHtml(
                    object.name
                  )}</td>
                  <td>${escapeHtml(
                    object.type
                  )}</td>
                  <td class="mono">
                    ${escapeHtml(
                      summarizeObject(object)
                    )}
                  </td>
                  <td class="mono">
                    ${escapeHtml(
                      object.path || ''
                    )}
                  </td>
                </tr>
                `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderSharedConfiguration(
  shared
) {
  if (!shared) {
    return '<p class="small">No shared configuration.</p>';
  }

  const blocks = [];

  if (shared.tags?.length) {
    blocks.push(`
      <h4>Tags</h4>
      ${renderRecordTable(
        shared.tags
      )}
    `);
  }

  if (shared.applications?.length) {
    blocks.push(`
      <h4>Applications</h4>
      ${renderRecordTable(
        shared.applications
      )}
    `);
  }

  if (shared.applicationGroups?.length) {
    blocks.push(`
      <h4>Application groups</h4>
      ${renderRecordTable(
        shared.applicationGroups
      )}
    `);
  }

  if (shared.applicationFilters?.length) {
    blocks.push(`
      <h4>Application filters</h4>
      ${renderRecordTable(
        shared.applicationFilters
      )}
    `);
  }

  if (shared.logSettings) {
    blocks.push(`
      <h4>Log settings</h4>
      ${renderProperties(
        shared.logSettings
      )}
    `);
  }

  return blocks.join('') ||
    '<p class="small">No additional shared sections.</p>';
}

function renderNetworkConfiguration(
  devices
) {
  const list =
    Object.values(devices || {});

  if (!list.length) {
    return '<p class="small">No device configuration.</p>';
  }

  return list
    .map(
      device => `
        <details open>
          <summary>
            <strong>
              ${escapeHtml(device.name)}
            </strong>
          </summary>

          <h4>System</h4>
          ${renderProperties(
            device.deviceconfig?.system
          )}

          <h4>Management</h4>
          ${renderProperties(
            device.deviceconfig?.management
          )}

          <h4>Interfaces</h4>
          ${renderRecordTable(
            device.network?.interfaces
          )}

          <h4>Zones</h4>
          ${renderRecordTable(
            device.network?.zones
          )}

          <h4>Virtual routers</h4>
          ${renderRecordTable(
            device.network?.virtualRouters
          )}

          <h4>DHCP</h4>
          ${renderRecordTable(
            device.network?.dhcp
          )}

          <h4>DNS proxy</h4>
          ${renderRecordTable(
            device.network?.dnsProxy
          )}

          <h4>IKE crypto profiles</h4>
          ${renderRecordTable(
            Object.values(
              device.network?.ike?.cryptoProfiles || {}
            ).flat()
          )}

          <h4>IKE gateways</h4>
          ${renderRecordTable(
            device.network?.ike?.gateways
          )}

          <h4>IPsec tunnels</h4>
          ${renderRecordTable(
            device.network?.ike?.ipsecTunnels
          )}

          <h4>PBF</h4>
          ${renderRecordTable(
            device.network?.pbfRules
          )}

          <h4>Device-level server profiles</h4>
          ${renderProfileCollections(
            device.deviceconfig?.serverProfiles
          )}
        </details>
      `
    )
    .join('');
}

function renderPolicyRulebases(
  devices
) {
  const output = [];

  for (const device of Object.values(
    devices || {}
  )) {
    for (const vsys of device.vsys || []) {
      output.push(`
        <details>
          <summary>
            <strong>
              ${escapeHtml(device.name)}
              /
              ${escapeHtml(vsys.name)}
            </strong>
          </summary>

          <h4>NAT</h4>
          ${renderRecordTable(
            vsys.natRules
          )}

          <h4>QoS</h4>
          ${renderRecordTable(
            vsys.qosRules
          )}

          <h4>Application Override</h4>
          ${renderRecordTable(
            vsys.applicationOverrideRules
          )}

          <h4>Decryption</h4>
          ${renderRecordTable(
            vsys.decryptionRules
          )}
        </details>
      `);
    }
  }

  return output.join('') ||
    '<p class="small">No additional policy rulebases.</p>';
}

function renderProfilesConfiguration(
  devices
) {
  const output = [];

  for (const device of Object.values(
    devices || {}
  )) {
    for (const vsys of device.vsys || []) {
      output.push(`
        <details>
          <summary>
            <strong>
              ${escapeHtml(device.name)}
              /
              ${escapeHtml(vsys.name)}
            </strong>
          </summary>

          <h4>Schedules</h4>
          ${renderRecordTable(
            vsys.schedules
          )}

          <h4>Security profiles</h4>
          ${renderProfileCollections(
            vsys.profiles
          )}

          <h4>Profile groups</h4>
          ${renderRecordTable(
            vsys.profileGroups
          )}

          <h4>Certificates</h4>
          ${renderRecordTable(
            vsys.certificates
          )}

          <h4>Authentication profiles</h4>
          ${renderRecordTable(
            vsys.authenticationProfiles
          )}

          <h4>Server profiles</h4>
          ${renderProfileCollections(
            vsys.serverProfiles
          )}

          <h4>GlobalProtect</h4>
          ${renderProfileCollections(
            vsys.globalProtect
          )}

          <h4>User-ID</h4>
          ${renderProfileCollections(
            vsys.userId
          )}

          <h4>HIP objects</h4>
          ${renderRecordTable(
            vsys.hipObjects
          )}

          <h4>HIP profiles</h4>
          ${renderRecordTable(
            vsys.hipProfiles
          )}
        </details>
      `);
    }
  }

  return output.join('') ||
    '<p class="small">No VSYS profile configuration.</p>';
}

function renderManagementState(
  configuration
) {
  const output = [];

  if (
    configuration?.management?.users?.length
  ) {
    output.push(`
      <h4>Management users</h4>
      ${renderRecordTable(
        configuration.management.users
      )}
    `);
  }

  if (
    configuration?.management?.passwordComplexity
  ) {
    output.push(`
      <h4>Password complexity</h4>
      ${renderProperties(
        configuration.management.passwordComplexity
      )}
    `);
  }

  if (
    configuration?.state?.readonly
  ) {
    output.push(`
      <h4>Read-only state</h4>
      ${renderProperties(
        configuration.state.readonly
      )}
    `);
  }

  if (
    configuration?.state?.configLocks?.length
  ) {
    output.push(`
      <h4>Configuration locks</h4>
      ${renderRecordTable(
        configuration.state.configLocks
      )}
    `);
  }

  if (
    configuration?.state?.audit?.length
  ) {
    output.push(`
      <h4>Audit</h4>
      ${renderRecordTable(
        configuration.state.audit
      )}
    `);
  }

  if (
    configuration?.templateStacks?.length
  ) {
    output.push(`
      <h4>Template stacks</h4>
      ${renderRecordTable(
        configuration.templateStacks
      )}
    `);
  }

  if (
    configuration?.templates?.length
  ) {
    output.push(`
      <h4>Templates</h4>
      ${renderRecordTable(
        configuration.templates
      )}
    `);
  }

  const plugins =
    Object.values(
      configuration?.devices || {}
    )
      .flatMap(
        device =>
          device.plugins || []
      );

  if (plugins.length) {
    output.push(`
      <h4>Plugins</h4>
      ${renderRecordTable(
        plugins
      )}
    `);
  }

  return output.join('') ||
    '<p class="small">No configuration-state sections.</p>';
}

function renderCoverage(
  coverage
) {
  if (!coverage) {
    return '<p class="small">No XML coverage data.</p>';
  }

  return `
    <div class="grid">
      <div class="stat">
        <span>Elements</span>
        <strong>${coverage.totalElements}</strong>
      </div>

      <div class="stat">
        <span>Leaf elements</span>
        <strong>${coverage.leafElements}</strong>
      </div>

      <div class="stat">
        <span>Attributes</span>
        <strong>${coverage.attributeCount}</strong>
      </div>

      <div class="stat">
        <span>Comments</span>
        <strong>${coverage.commentCount}</strong>
      </div>

      <div class="stat">
        <span>Unclassified roots</span>
        <strong>
          ${coverage.unrecognizedMajorSections.length}
        </strong>
      </div>
    </div>

    <p class="small">
      Recognized root sections:
      ${coverage.recognizedMajorSections
        .map(
          x => `<code>${escapeHtml(x)}</code>`
        )
        .join(' ')}
    </p>

    ${
      coverage.unrecognizedMajorSections.length
        ? `
          <div class="status warning">
            Unclassified root sections:
            ${coverage.unrecognizedMajorSections
              .map(
                x =>
                  `<code>${escapeHtml(x)}</code>`
              )
              .join(' ')}
            .
            Their contents remain in the XML inventory.
          </div>
        `
        : `
          <div class="status success">
            All root-level XML sections are either semantically classified
            or retained by the generic inventory.
          </div>
        `
    }
  `;
}

function renderXmlInventory(
  inventory
) {
  if (!inventory.length) {
    return '<p class="small">No XML inventory.</p>';
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Kind</th>
            <th>Path</th>
            <th>Name</th>
            <th>Value</th>
            <th>Attributes</th>
          </tr>
        </thead>
        <tbody>
          ${inventory
            .map(
              item =>
                `
                <tr>
                  <td>${escapeHtml(
                    item.kind
                  )}</td>

                  <td class="mono">
                    ${escapeHtml(
                      item.path
                    )}
                  </td>

                  <td>
                    ${escapeHtml(
                      item.name
                    )}
                  </td>

                  <td class="mono">
                    ${escapeHtml(
                      redactDisplayValue(
                        item.value,
                        item.name
                      )
                    )}
                  </td>

                  <td class="mono">
                    ${escapeHtml(
                      JSON.stringify(
                        redactAttributes(
                          item.attributes,
                          item.name
                        )
                      )
                    )}
                  </td>
                </tr>
                `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderRecordTable(
  records
) {
  if (!records?.length) {
    return '<p class="small">None.</p>';
  }

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Path</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          ${records
            .map(
              record =>
                `
                <tr>
                  <td>${escapeHtml(
                    record.name || ''
                  )}</td>

                  <td>${escapeHtml(
                    record.type || ''
                  )}</td>

                  <td class="mono">
                    ${escapeHtml(
                      record.path || ''
                    )}
                  </td>

                  <td class="mono">
                    ${escapeHtml(
                      summarizeRecord(
                        record
                      )
                    )}
                  </td>
                </tr>
                `
            )
            .join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderSimpleRecords(
  records
) {
  return renderRecordTable(
    records
  );
}

function renderProfileCollections(
  collections
) {
  if (!collections) {
    return '<p class="small">None.</p>';
  }

  if (Array.isArray(collections)) {
    return renderRecordTable(
      collections
    );
  }

  const chunks = [];

  for (const [
    key,
    values
  ] of Object.entries(
    collections
  )) {
    if (
      !Array.isArray(values) ||
      !values.length
    ) {
      continue;
    }

    chunks.push(`
      <h5>${escapeHtml(key)}</h5>
      ${renderRecordTable(values)}
    `);
  }

  return chunks.join('') ||
    '<p class="small">None.</p>';
}

function renderProperties(
  object
) {
  if (!object) {
    return '<p class="small">None.</p>';
  }

  return `
    <pre
      class="mono"
      style="white-space:pre-wrap"
    >${escapeHtml(
      JSON.stringify(
        redactSensitiveData(object),
        null,
        2
      )
    )}</pre>
  `;
}

function summarizeObject(
  object
) {
  if (
    object.type === 'address'
  ) {
    return (
      object.value ||
      object.ipNetmask ||
      object.fqdn ||
      '—'
    );
  }

  if (
    Array.isArray(
      object.members
    )
  ) {
    return (
      object.members.join(', ') ||
      '—'
    );
  }

  if (
    Array.isArray(
      object.protocols
    )
  ) {
    return object.protocols
      .map(
        protocol =>
          `${protocol.protocol}:${(
            protocol.ports || []
          ).join(',') || '—'}`
      )
      .join(' | ');
  }

  if (
    object.filter
  ) {
    return `dynamic filter: ${object.filter}`;
  }

  if (
    object.color
  ) {
    return `color=${object.color}`;
  }

  return summarizeRecord(
    object
  );
}

function summarizeRecord(
  record
) {
  const properties =
    record.properties;

  if (!properties) {
    return '—';
  }

  const parts = [];

  for (const key of [
    'ip-netmask',
    'fqdn',
    'description',
    'filter',
    'action',
    'port',
    'class',
    'metric',
    'lease',
    'destination',
    'peer-ip',
    'tunnel-interface',
    'certificate',
    'analysis'
  ]) {
    const values =
      findLeafValues(
        properties,
        key
      );

    if (values.length) {
      parts.push(
        `${key}=${values.join('|')}`
      );
    }
  }

  return (
    parts.join('; ') ||
    JSON.stringify(
      redactSensitiveData(
        properties
      )
    ).slice(
      0,
      1200
    )
  );
}

function renderList(
  values
) {
  if (!values?.length) {
    return '<span class="small">—</span>';
  }

  return values
    .map(
      value =>
        `<code>${escapeHtml(value)}</code>`
    )
    .join(' ');
}

/* -------------------------------------------------------------------------- */
/* SAFE DISPLAY / EXPORT                                                      */
/* -------------------------------------------------------------------------- */

function isSensitiveName(
  name
) {
  return /(?:password|phash|private-key|pre-shared-key|bind-password|secret|passphrase)$/i
    .test(
      String(name || '')
    );
}

function redactDisplayValue(
  value,
  name
) {
  if (
    isSensitiveName(name)
  ) {
    return '[redacted]';
  }

  return String(
    value ?? ''
  );
}

function redactAttributes(
  attributes,
  parentName = ''
) {
  const output = {};

  for (const [
    key,
    value
  ] of Object.entries(
    attributes || {}
  )) {
    output[key] =
      isSensitiveName(key) ||
      isSensitiveName(parentName)
        ? '[redacted]'
        : value;
  }

  return output;
}

function redactSensitiveData(
  value,
  key = ''
) {
  if (
    isSensitiveName(key)
  ) {
    return '[redacted]';
  }

  if (Array.isArray(value)) {
    return value.map(
      item =>
        redactSensitiveData(
          item,
          key
        )
    );
  }

  if (
    !value ||
    typeof value !==
      'object'
  ) {
    return value;
  }

  const output = {};

  for (const [
    childKey,
    childValue
  ] of Object.entries(
    value
  )) {
    output[childKey] =
      redactSensitiveData(
        childValue,
        childKey
      );
  }

  return output;
}

function parseSetConfig(text) {
  const rules = [];
  const objects = [];
  const interfaces = [];
  const zones = [];
  const metadata = {};

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const tokens = tokenizeSet(line);
    if (!tokens.length || tokens[0].toLowerCase() !== 'set') continue;

    const lower = line.toLowerCase();

    if (lower.includes('rulebase security rules')) {
      const rule = parseSetRule(tokens);
      if (rule) rules.push(rule);
      continue;
    }

    if (lower.includes('deviceconfig') && lower.includes('hostname')) {
      const i = tokens.findIndex(x => x.toLowerCase() === 'hostname');
      if (i >= 0 && tokens[i + 1]) metadata.hostname = tokens[i + 1];
      continue;
    }

    if (lower.includes('address ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'address');
      if (idx >= 0 && tokens[idx + 1]) {
        objects.push({
          name: tokens[idx + 1],
          type: 'address',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
      continue;
    }

    if (lower.includes('address-group ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'address-group');
      if (idx >= 0 && tokens[idx + 1]) {
        objects.push({
          name: tokens[idx + 1],
          type: 'address-group',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
      continue;
    }

    if (lower.includes('network interface ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'interface');
      if (idx >= 0 && tokens[idx + 1]) {
        interfaces.push({
          name: tokens[idx + 1],
          type: 'interface',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
    }

    if (lower.includes('network virtual-router') &&
        lower.includes('interface')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'interface');
      if (idx >= 0 && tokens[idx + 1]) {
        interfaces.push({
          name: tokens[idx + 1],
          type: 'virtual-router interface',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
    }
  }

  return {
    rules: mergeSetRules(rules),
    objects,
    interfaces,
    zones,
    metadata
  };
}

function parseSetRule(tokens) {
  const ruleIndex = tokens.findIndex(
    x => x.toLowerCase() === 'rules'
  );
  if (ruleIndex < 0 || !tokens[ruleIndex + 1]) return null;

  const name = tokens[ruleIndex + 1];
  const rest = tokens.slice(ruleIndex + 2);

  const rule = {
    name,
    source: 'set',
    from: [],
    to: [],
    sourceAddresses: [],
    destinationAddresses: [],
    applications: [],
    services: [],
    categories: [],
    users: [],
    action: 'unknown',
    disabled: false,
    logStart: false,
    logEnd: false,
    description: ''
  };

  const fields = {
    from: 'from',
    to: 'to',
    source: 'sourceAddresses',
    destination: 'destinationAddresses',
    application: 'applications',
    service: 'services',
    category: 'categories',
    'source-user': 'users'
  };

  for (let i = 0; i < rest.length; i++) {
    const key = rest[i];
    const prop = fields[key];

    if (prop) {
      const vals = [];
      i++;
      while (i < rest.length &&
             !fields[rest[i]] &&
             !['action', 'disabled', 'log-start', 'log-end', 'description']
               .includes(rest[i])) {
        vals.push(rest[i]);
        i++;
      }
      i--;
      rule[prop].push(...vals);
      continue;
    }

    if (key === 'action' && rest[i + 1]) {
      rule.action = rest[++i];
    } else if (key === 'disabled' && rest[i + 1]) {
      rule.disabled = rest[++i] === 'yes';
    } else if (key === 'log-start' && rest[i + 1]) {
      rule.logStart = rest[++i] === 'yes';
    } else if (key === 'log-end' && rest[i + 1]) {
      rule.logEnd = rest[++i] === 'yes';
    } else if (key === 'description' && rest[i + 1]) {
      rule.description = rest[++i];
    }
  }

  return rule;
}

function mergeSetRules(rules) {
  const map = new Map();

  for (const rule of rules) {
    const existing = map.get(rule.name);
    if (!existing) {
      map.set(rule.name, rule);
      continue;
    }

    for (const key of [
      'from',
      'to',
      'sourceAddresses',
      'destinationAddresses',
      'applications',
      'services',
      'categories',
      'users'
    ]) {
      existing[key] = unique([...existing[key], ...rule[key]]);
    }

    if (rule.action !== 'unknown') existing.action = rule.action;
    existing.disabled ||= rule.disabled;
    existing.logStart ||= rule.logStart;
    existing.logEnd ||= rule.logEnd;
    if (rule.description) existing.description = rule.description;
  }

  return [...map.values()];
}

function parseRuleCsv(text) {
  const rows = parseCsv(text);
  if (!rows.length) return [];

  const headers = rows[0].map(normalizeHeader);
  const rules = [];

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (!row.some(Boolean)) continue;

    const get = (...names) => {
      for (const name of names) {
        const idx = headers.indexOf(normalizeHeader(name));
        if (idx >= 0) return row[idx] || '';
      }
      return '';
    };

    rules.push({
      name: get('name', 'rule', 'rule name') || `Rule ${i}`,
      source: 'CSV',
      from: splitField(get('from', 'source zone')),
      to: splitField(get('to', 'destination zone')),
      sourceAddresses: splitField(get('source', 'source address', 'source addresses')),
      destinationAddresses: splitField(get('destination', 'destination address', 'destination addresses')),
      applications: splitField(get('application', 'applications')),
      services: splitField(get('service', 'services')),
      categories: splitField(get('category', 'categories', 'url category')),
      users: splitField(get('source-user', 'source user', 'users')),
      action: get('action') || 'unknown',
      disabled: /^(yes|true|disabled)$/i.test(get('disabled')),
      logStart: /^(yes|true)$/i.test(get('log-start')),
      logEnd: /^(yes|true)$/i.test(get('log-end')),
      description: get('description')
    });
  }

  return rules;
}

function parseTextShow(text) {
  const rules = [];
  const objects = [];
  const interfaces = [];
  const zones = [];
  const metadata = {};

  const lines = text.split(/\r?\n/);
  let currentRule = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;

    const hostname = line.match(/hostname\s*[:=]\s*(.+)$/i);
    if (hostname) metadata.hostname = hostname[1].trim();

    const ruleHeader = line.match(
      /(?:rule(?:base)?\s+security\s+rules?|security\s+rule)\s*[:=]?\s*(.+)$/i
    );

    if (ruleHeader) {
      if (currentRule) rules.push(currentRule);
      currentRule = emptyRule(ruleHeader[1].trim(), 'text');
      continue;
    }

    if (!currentRule) continue;

    const pair = line.match(/^([A-Za-z][A-Za-z _-]*)\s*[:=]\s*(.*)$/);
    if (!pair) continue;

    const key = normalizeHeader(pair[1]);
    const value = pair[2].trim();

    if (key === 'from') currentRule.from = splitField(value);
    else if (key === 'to') currentRule.to = splitField(value);
    else if (key === 'source') currentRule.sourceAddresses = splitField(value);
    else if (key === 'destination') currentRule.destinationAddresses = splitField(value);
    else if (key === 'application') currentRule.applications = splitField(value);
    else if (key === 'service') currentRule.services = splitField(value);
    else if (key === 'category') currentRule.categories = splitField(value);
    else if (key === 'source user') currentRule.users = splitField(value);
    else if (key === 'action') currentRule.action = value;
    else if (key === 'description') currentRule.description = value;
    else if (key === 'disabled') currentRule.disabled = /yes|true/i.test(value);
  }

  if (currentRule) rules.push(currentRule);

  return { rules, objects, interfaces, zones, metadata };
}

function analyzeRules(rules) {
  const findings = [];
  const shadowCandidates = [];

  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    const name = r.name;

    if (r.disabled) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'DISABLED_RULE',
        text: 'Rule is disabled.'
      });
    }

    if (isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.applications) &&
        isAny(r.services)) {
      findings.push({
        severity: 'warn',
        rule: name,
        code: 'VERY_BROAD_RULE',
        text: 'Source, destination, application and service are all effectively any. This rule can match a very large portion of traffic.'
      });
    }

    if (isAny(r.sourceAddresses)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_SOURCE',
        text: 'Source address is any.'
      });
    }

    if (isAny(r.destinationAddresses)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_DESTINATION',
        text: 'Destination address is any.'
      });
    }

    if (isAny(r.applications)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_APPLICATION',
        text: 'Application is any. Port/service matching may therefore carry more of the policy burden.'
      });
    }

    if (isAny(r.services)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_SERVICE',
        text: 'Service is any.'
      });
    }

    if (/^(allow|permit)$/i.test(r.action) &&
        isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.services)) {
      findings.push({
        severity: 'warn',
        rule: name,
        code: 'BROAD_ALLOW',
        text: 'Allow rule has any source, destination and service. Review whether the scope is intentional.'
      });
    }

    if (/^(deny|drop|reject)$/i.test(r.action) &&
        isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.applications) &&
        isAny(r.services)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'CATCH_ALL_DENY',
        text: 'This looks like a catch-all deny rule, commonly used as a final policy boundary.'
      });
    }

    if (r.logStart && r.logEnd) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'LOG_START_END',
        text: 'Both session start and session end logging are enabled.'
      });
    }

    if (r.from.length && r.to.length &&
        r.from.some(x => x.toLowerCase() === 'any') &&
        r.to.some(x => x.toLowerCase() === 'any')) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_ZONES',
        text: 'Both source and destination zones are any.'
      });
    }

    shadowCandidates.push(r);
  }

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const a = rules[i];
      const b = rules[j];

      if (a.disabled || b.disabled) continue;
      if (!sameMatchScope(a, b)) continue;

      const aa = String(a.action).toLowerCase();
      const ba = String(b.action).toLowerCase();

      if (aa !== ba) {
        findings.push({
          severity: 'warn',
          rule: b.name,
          code: 'POTENTIAL_CONFLICT',
          text: `Rule "${b.name}" has the same parsed match scope as earlier rule "${a.name}", but a different action (${a.action} vs ${b.action}). In PAN-OS policy evaluation, rule order is therefore important.`
        });
      } else if (i < j) {
        findings.push({
          severity: 'info',
          rule: b.name,
          code: 'POTENTIAL_SHADOW',
          text: `Rule "${b.name}" appears to duplicate the parsed match scope of earlier rule "${a.name}".`
        });
      }
    }
  }

  if (rules.length) {
    const last = rules[rules.length - 1];
    if (/^(allow|permit)$/i.test(last.action) &&
        isAny(last.sourceAddresses) &&
        isAny(last.destinationAddresses)) {
      findings.push({
        severity: 'warn',
        rule: last.name,
        code: 'FINAL_BROAD_ALLOW',
        text: 'The final parsed rule is a broad allow. Verify that this is intentional; later policy entries cannot restrict traffic already matched by an earlier rule.'
      });
    }
  }

  return findings;
}

function buildStats(rules, findings) {
  return {
    totalRules: rules.length,
    enabledRules: rules.filter(r => !r.disabled).length,
    disabledRules: rules.filter(r => r.disabled).length,
    allowRules: rules.filter(r => /^(allow|permit)$/i.test(r.action)).length,
    denyRules: rules.filter(r => /^(deny|drop|reject)$/i.test(r.action)).length,
    unknownActions: rules.filter(r => !/^(allow|permit|deny|drop|reject)$/i.test(r.action)).length,
    warnings: findings.filter(f => f.severity === 'warn').length,
    info: findings.filter(f => f.severity === 'info').length
  };
}

function emptyRule(name, source) {
  return {
    name,
    source,
    from: [],
    to: [],
    sourceAddresses: [],
    destinationAddresses: [],
    applications: [],
    services: [],
    categories: [],
    users: [],
    action: 'unknown',
    disabled: false,
    logStart: false,
    logEnd: false,
    description: ''
  };
}

function childValues(node, name) {
  const parent = Array.from(node.children).find(
    x => x.tagName.toLowerCase() === name.toLowerCase()
  );
  if (!parent) return [];

  return Array.from(parent.children)
    .map(x => (x.textContent || '').trim())
    .filter(Boolean);
}

function childText(node, selector) {
  const found = node.querySelector(`:scope > ${selector}`);
  return found ? found.textContent.trim() : '';
}

function attrOrChild(node, name) {
  return node.getAttribute(name) || childText(node, name);
}

function firstXmlText(doc, selectors) {
  for (const selector of selectors) {
    const n = doc.querySelector(selector);
    if (n?.textContent?.trim()) return n.textContent.trim();
  }
  return '';
}

function directValue(node) {
  const parts = [];
  for (const child of node.children) {
    const text = child.textContent?.trim();
    if (text) parts.push(`${child.tagName}=${text}`);
  }
  return parts.join('; ');
}

function tokenizeSet(line) {
  const out = [];
  const re = /"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) {
    const value = m[1] ?? m[2] ?? m[3];
    out.push(value.replace(/\\(["'])/g, '$1'));
  }
  return out;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (c === '"') {
      if (quoted && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (c === ',' && !quoted) {
      row.push(cell);
      cell = '';
    } else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += c;
    }
  }

  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }

  return rows;
}

function normalizeHeader(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ');
}

function splitField(value) {
  if (!value) return [];
  return String(value)
    .split(/[;,|]/)
    .map(x => x.trim())
    .filter(Boolean);
}

function list(values) {
  const v = values?.length ? values : ['any'];
  return v.map(x => `<code>${escapeHtml(x)}</code>`).join(' ');
}

function isAny(values) {
  return !values?.length ||
    values.some(v => ['any', 'all', '*'].includes(String(v).trim().toLowerCase()));
}

function setEqual(a, b) {
  const x = new Set((a || []).map(v => String(v).toLowerCase()));
  const y = new Set((b || []).map(v => String(v).toLowerCase()));
  if (x.size !== y.size) return false;
  for (const v of x) if (!y.has(v)) return false;
  return true;
}

async function readLocalFile(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    try {
      return new TextDecoder('windows-1252').decode(bytes);
    } catch {
      return new TextDecoder().decode(bytes);
    }
  }
}