import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';
export const metadata = {
  id: 'sap-landscape',
  title: 'SAP GUI Landscape Analyzer',
  description: 'Parse SAP GUI landscape XML and identify risky or atypical configurations',
  path: '/#sap-landscape'
};
export function renderSapLandscape(app) {
  app.innerHTML = `
    <div class="tool-window" id="sapLandscapeWindow">
    <div class="tool-window-header" id="sapLandscapeDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>SAP GUI Landscape Analyzer</strong>
    </div>
    <section class="card">
        <p class="small">
        Analyze SAP GUI landscape XML locally. Identify suspicious settings, incomplete connections, duplicate entries, insecure references and unusual connection configurations.
        </p>
        <div class="notice">
        <strong>Local analysis only.</strong>
        Files are not uploaded. External landscape includes are reported but never fetched. Findings are configuration indicators, not proof that a system is vulnerable.
        </div>
        <div class="tool-section">
        <label for="sapLandscapeFile">
            Select SAP landscape XML
        </label>
        <input
            id="sapLandscapeFile"
            type="file"
            accept=".xml,.txt,application/xml,text/xml"
        />
        <div class="tool-toolbar">
            <button class="btn primary" id="sapLandscapeAnalyze">
            Analyze XML
            </button>
            <button class="btn" id="sapLandscapeExample">
            Load example
            </button>
            <button class="btn" id="sapLandscapeClear">
            Clear
            </button>
        </div>
        <label for="sapLandscapeInput">
            XML input
        </label>
        <textarea
            id="sapLandscapeInput"
            rows="12"
            spellcheck="false"
            placeholder="Paste SAPUILandscape.xml or SAPUILandscapeGlobal.xml here..."
        ></textarea>
        </div>
        <div id="sapLandscapeStatus" aria-live="polite"></div>
        <div id="sapLandscapeResults"></div>
        <div id="sapLandscapeExports" hidden>
        <div class="tool-toolbar">
            <button class="btn" id="sapLandscapeExportJson">
            Export JSON report
            </button>
            <button class="btn" id="sapLandscapeExportText">
            Export text report
            </button>
        </div>
        </div>
    </section>
    </div>
  `;
  enableToolDragging(
    $('#sapLandscapeWindow'),
    $('#sapLandscapeDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
  const input = $('#sapLandscapeInput');
  const fileInput = $('#sapLandscapeFile');
  const status = $('#sapLandscapeStatus');
  const results = $('#sapLandscapeResults');
  const exports = $('#sapLandscapeExports');
  let lastReport = null;
  fileInput.addEventListener('change', async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      input.value = await file.text();
      analyze();
    } catch {
      showStatus('Unable to read the selected file.', 'danger');
    }
  });
  $('#sapLandscapeAnalyze').addEventListener('click', analyze);
  $('#sapLandscapeExample').addEventListener('click', () => {
    input.value = createExample();
    analyze();
  });
  $('#sapLandscapeClear').addEventListener('click', () => {
    input.value = '';
    fileInput.value = '';
    status.innerHTML = '';
    results.innerHTML = '';
    exports.hidden = true;
    lastReport = null;
  });
  $('#sapLandscapeExportJson').addEventListener('click', () => {
    if (!lastReport) return;
    downloadText(
      'sap-landscape-analysis.json',
      JSON.stringify(lastReport, null, 2),
      'application/json;charset=utf-8'
    );
  });
  $('#sapLandscapeExportText').addEventListener('click', () => {
    if (!lastReport) return;
    downloadText(
      'sap-landscape-analysis.txt',
      createTextReport(lastReport),
      'text/plain;charset=utf-8'
    );
  });
  function analyze() {
    const xmlText = input.value.trim();
    if (!xmlText) {
      showStatus('Select a file or paste XML first.', 'danger');
      return;
    }
    try {
      const documentNode = new DOMParser().parseFromString(
        xmlText,
        'application/xml'
      );
      if (
        documentNode.getElementsByTagName('parsererror').length > 0 ||
        !documentNode.documentElement ||
        localName(documentNode.documentElement) !== 'Landscape'
      ) {
        throw new Error(
          'Invalid XML or unexpected root element. Expected <Landscape>.'
        );
      }
      lastReport = analyzeDocument(documentNode);
      renderReport(lastReport);
      exports.hidden = false;
      const counts = countSeverities(lastReport.findings);
      showStatus(
        `Analysis complete: ${lastReport.summary.services} services, ` +
        `${lastReport.summary.messageServers} message servers, ` +
        `${lastReport.summary.routers} routers, ` +
        `${lastReport.summary.includes} includes. ` +
        `${counts.critical + counts.high} high-priority finding(s), ` +
        `${counts.medium} medium, ${counts.low} low.`,
        counts.critical + counts.high > 0 ? 'warn' : 'ok'
      );
    } catch (error) {
      lastReport = null;
      results.innerHTML = '';
      exports.hidden = true;
      showStatus(error.message || 'Unable to parse this XML.', 'danger');
    }
  }
  function analyzeDocument(doc) {
    const root = doc.documentElement;
    const services = elements(doc, 'Service').map((element, index) => {
      return readElement(element, index);
    });
    const messageServers = elements(doc, 'Messageserver').map(element => {
      return readElement(element);
    });
    const routers = elements(doc, 'Router').map(element => {
      return readElement(element);
    });
    const includes = elements(doc, 'Include').map(element => {
      return readElement(element);
    });
    const workspaces = elements(doc, 'Workspace').map(element => {
      return readElement(element);
    });
    const findings = [];
    checkXmlRoot(root, findings);
    checkIncludes(includes, findings);
    checkServices(services, findings);
    checkMessageServers(messageServers, findings);
    checkRouters(routers, findings);
    checkDuplicateIds(services, 'Service', findings);
    checkDuplicateIds(messageServers, 'Messageserver', findings);
    checkDuplicateIds(routers, 'Router', findings);
    checkDuplicateNames(services, findings);
    checkDuplicateEndpoints(services, findings);
    checkRouterReferences(services, routers, findings);
    checkWorkspaceReferences(doc, services, findings);
    return {
      tool: 'SAP GUI Landscape Analyzer',
      reportVersion: 1,
      analyzedAt: new Date().toISOString(),
      source: {
        rootElement: root.nodeName,
        version: root.getAttribute('version') || '',
        updated: root.getAttribute('updated') || '',
        generator: root.getAttribute('generator') || ''
      },
      summary: {
        services: services.length,
        messageServers: messageServers.length,
        routers: routers.length,
        includes: includes.length,
        workspaces: workspaces.length,
        findings: findings.length
      },
      services,
      messageServers,
      routers,
      includes,
      workspaces,
      findings
    };
  }
  function readElement(element, index = null) {
    const attributes = {};
    for (const attribute of Array.from(element.attributes || [])) {
      attributes[attribute.name] = attribute.value;
    }
    const children = {};
    for (const child of Array.from(element.children || [])) {
      const name = localName(child);
      if (!children[name]) children[name] = [];
      children[name].push(child.textContent.trim());
    }
    return {
      index,
      element: localName(element),
      name: attr(element, 'name'),
      uuid: attr(element, 'uuid'),
      type: attr(element, 'type'),
      description: attr(element, 'description'),
      systemId: attr(element, 'systemid'),
      client: attr(element, 'client'),
      server: attr(element, 'server'),
      group: attr(element, 'group'),
      routerId: attr(element, 'routerid'),
      messageServerId: attr(element, 'messageserverid'),
      sncEnabled: attr(element, 'sncop'),
      sncName: attr(element, 'sncname'),
      url: attr(element, 'url'),
      port: attr(element, 'port'),
      attributes,
      children
    };
  }
  function checkXmlRoot(root, findings) {
    const version = root.getAttribute('version');
    const updated = root.getAttribute('updated');
    if (!version) {
      addFinding(
        findings,
        'low',
        'ROOT_VERSION_MISSING',
        'Landscape version attribute is missing',
        'The root element does not contain a version attribute.',
        'Confirm whether this file was generated by the expected SAP GUI version.'
      );
    }
    if (updated && Number.isNaN(Date.parse(updated))) {
      addFinding(
        findings,
        'low',
        'ROOT_UPDATED_INVALID',
        'Unrecognized landscape update timestamp',
        `The updated attribute is not a recognizable date: ${updated}`,
        'Verify the timestamp against the expected landscape format.'
      );
    }
  }
  function checkIncludes(includes, findings) {
    if (includes.length === 0) return;
    for (const include of includes) {
      const url = include.url.trim();
      if (!url) {
        addFinding(
          findings,
          'medium',
          'INCLUDE_URL_MISSING',
          'Include has no URL',
          'An Include element has no url attribute.',
          'Check whether the include is incomplete or generated incorrectly.',
          include.name
        );
        continue;
      }
      if (/^http:\/\//i.test(url)) {
        addFinding(
          findings,
          'high',
          'INCLUDE_HTTP',
          'Landscape include uses plain HTTP',
          'The referenced landscape URL uses HTTP rather than HTTPS. Its integrity and confidentiality may not be protected in transit.',
          'Prefer an approved HTTPS endpoint where supported by the SAP GUI version and environment.',
          url
        );
      } else if (/^https:\/\//i.test(url)) {
        addFinding(
          findings,
          'low',
          'INCLUDE_HTTPS_REVIEW',
          'External landscape include',
          'The landscape references an external HTTPS resource. This tool does not retrieve or validate it.',
          'Confirm that the host is an approved configuration source and that the included file is administered appropriately.',
          url
        );
      } else if (/^file:\/\//i.test(url)) {
        addFinding(
          findings,
          'low',
          'INCLUDE_FILE_URL',
          'File-based landscape include',
          'The landscape references a local file or file share.',
          'Confirm that the path is expected and access is restricted to authorized administrators.',
          url
        );
      } else if (/^\\\\/.test(url)) {
        addFinding(
          findings,
          'low',
          'INCLUDE_NETWORK_PATH',
          'Network-share landscape include',
          'The landscape references a network path.',
          'Verify share permissions, write access and the integrity of the distributed file.',
          url
        );
      } else if (/^[a-z][a-z0-9+.-]*:/i.test(url)) {
        addFinding(
          findings,
          'medium',
          'INCLUDE_UNUSUAL_SCHEME',
          'Unusual include URL scheme',
          'The include uses a scheme that this analyzer does not recognize as a typical landscape reference.',
          'Confirm that the scheme is supported and approved in your environment.',
          url
        );
      }
      if (/^https?:\/\//i.test(url)) {
        try {
          const parsed = new URL(url);
          if (parsed.username || parsed.password) {
            addFinding(
              findings,
              'high',
              'URL_EMBEDDED_CREDENTIALS',
              'URL contains embedded credentials',
              'The include URL contains a username or password component.',
              'Remove credentials from the URL and use an approved authentication mechanism.',
              parsed.origin
            );
          }
          if (parsed.search || parsed.hash) {
            addFinding(
              findings,
              'low',
              'INCLUDE_URL_EXTRA_COMPONENTS',
              'Include URL contains query or fragment data',
              'The URL includes a query string or fragment.',
              'Verify that these components are expected and do not expose sensitive data.',
              parsed.origin
            );
          }
        } catch {
          addFinding(
            findings,
            'medium',
            'INCLUDE_URL_INVALID',
            'Include URL could not be parsed',
            'The URL resembles an HTTP(S) URL but could not be parsed normally.',
            'Check the URL syntax and verify the intended target.'
          );
        }
      }
    }
    if (includes.length > 10) {
      addFinding(
        findings,
        'low',
        'MANY_INCLUDES',
        'Large number of landscape includes',
        `The file contains ${includes.length} Include entries.`,
        'Review the include hierarchy and confirm that all references are required.'
      );
    }
  }
  function checkServices(services, findings) {
    if (services.length === 0) {
      addFinding(
        findings,
        'low',
        'NO_SERVICES',
        'No service entries found',
        'No Service elements were found in the landscape XML.',
        'This may be valid for an include-only file or a file containing only global definitions.'
      );
    }
    for (const service of services) {
      const label = service.name || service.uuid || `Service #${service.index + 1}`;
      const attrs = service.attributes;
      const type = (service.type || '').toUpperCase();
      if (!service.name) {
        addFinding(
          findings,
          'low',
          'SERVICE_NAME_MISSING',
          'Service has no name',
          'The service entry does not have a name attribute.',
          'Add a clear, recognizable connection name if this is an end-user connection.',
          label
        );
      }
      if (!service.uuid) {
        addFinding(
          findings,
          'medium',
          'SERVICE_UUID_MISSING',
          'Service UUID is missing',
          'The service entry has no UUID.',
          'Check the file against the schema and the SAP GUI version that consumes it.',
          label
        );
      }
      if (!service.type) {
        addFinding(
          findings,
          'medium',
          'SERVICE_TYPE_MISSING',
          'Service type is missing',
          'The service entry does not specify a type attribute.',
          'Confirm that the entry is complete and compatible with the target SAP GUI version.',
          label
        );
      } else if (![
        'SAPGUI',
        'FIORI',
        'NWBC',
        'WEB',
        'PORTAL',
        'SEARCH'
      ].includes(type)) {
        addFinding(
          findings,
          'low',
          'SERVICE_TYPE_UNUSUAL',
          'Unrecognized service type',
          `The service type "${service.type}" is not in this tool's common-type list.`,
          'Verify the type against the SAP GUI version and service definition. This may be a valid version-specific type.',
          label
        );
      }
      const isWebType = ['FIORI', 'NWBC', 'WEB', 'PORTAL'].includes(type);
      if (isWebType && service.url) {
        checkServiceUrl(service, findings, label);
      }
      if (!isWebType && !service.server && !service.group) {
        addFinding(
          findings,
          'medium',
          'SERVICE_TARGET_MISSING',
          'Service has no server or group',
          'The service has neither a server attribute nor a group attribute.',
          'Check whether the connection target or message-server group is missing.',
          label
        );
      }
      if (service.server && isLoopbackOrWildcard(service.server)) {
        addFinding(
          findings,
          'medium',
          'SERVICE_LOOPBACK_TARGET',
          'Service targets a loopback or wildcard address',
          `The server value is "${service.server}".`,
          'Confirm that this is intentional. Loopback targets are unusual for shared enterprise SAP landscapes.',
          label
        );
      }
      if (service.systemId && !/^[A-Z0-9]{3}$/.test(service.systemId)) {
        addFinding(
          findings,
          'low',
          'SYSTEM_ID_UNUSUAL',
          'System ID has an atypical format',
          `The system ID "${service.systemId}" is not three uppercase letters or digits.`,
          'Verify the system ID with the SAP administrators. Treat this as a heuristic, not a validity rule.',
          label
        );
      }
      if (service.client && !/^\d{3}$/.test(service.client)) {
        addFinding(
          findings,
          'low',
          'CLIENT_UNUSUAL',
          'Client value has an atypical format',
          `The client value "${service.client}" is not three digits.`,
          'Confirm whether the client format is valid for this connection type and SAP environment.',
          label
        );
      }
      if (attrs.sncop !== undefined) {
        const sncop = attrs.sncop.trim();
        if (sncop === '0') {
          addFinding(
            findings,
            'medium',
            'SNC_DISABLED',
            'SNC is explicitly disabled',
            'The sncop value is 0, which SAP documentation identifies as disabling single sign-on through SNC.',
            'Confirm that this is allowed by your security policy, especially for production or privileged connections.',
            label
          );
        } else if (!['1', '2', '3'].includes(sncop)) {
          addFinding(
            findings,
            'low',
            'SNC_OPTION_UNUSUAL',
            'Unrecognized SNC option',
            `The sncop value is "${sncop}".`,
            'Verify the value against the SAP GUI version and your SNC configuration.',
            label
          );
        }
      }
      if (attrs.sncop !== undefined && attrs.sncop.trim() !== '0' && !service.sncName) {
        addFinding(
          findings,
          'medium',
          'SNC_NAME_MISSING',
          'SNC option set but SNC name is missing',
          'An sncop value is configured, but no sncname attribute was found.',
          'Check whether the SNC configuration is complete for this connection.',
          label
        );
      }
      if (service.sncName && /password|passwd|secret/i.test(service.sncName)) {
        addFinding(
          findings,
          'medium',
          'SNC_NAME_SUSPICIOUS',
          'SNC name contains a credential-related term',
          'The SNC name contains text resembling a password or secret reference.',
          'Review the value. This may be a harmless naming convention or an accidental disclosure.',
          label
        );
      }
      const routerValue = findAttribute(attrs, [
        'router',
        'routerstring',
        'saprouter'
      ]);
      if (routerValue) {
        checkRouterString(routerValue, label, findings);
      }
      for (const [key, value] of Object.entries(attrs)) {
        if (/password|passwd|secret|token/i.test(key) && value) {
          addFinding(
            findings,
            'high',
            'POSSIBLE_SECRET_ATTRIBUTE',
            'Potential secret stored in a service attribute',
            `The attribute "${key}" contains a non-empty value.`,
            'Verify whether this attribute is sensitive and remove embedded secrets from distributed landscape files.',
            label
          );
        }
        if (/^http:\/\//i.test(value) && /url|web|status/i.test(key)) {
          addFinding(
            findings,
            'medium',
            'SERVICE_HTTP_ATTRIBUTE',
            'Service attribute contains an HTTP URL',
            `The attribute "${key}" uses plain HTTP.`,
            'Confirm whether HTTP is required. Prefer HTTPS for web endpoints where supported.',
            label
          );
        }
      }
    }
  }
  function checkServiceUrl(service, findings, label) {
    try {
      const parsed = new URL(service.url);
      if (parsed.protocol === 'http:') {
        addFinding(
          findings,
          'high',
          'SERVICE_HTTP_URL',
          'Web service uses plain HTTP',
          'The service URL uses HTTP rather than HTTPS.',
          'Use HTTPS where supported and approved, and verify certificate validation and endpoint ownership.',
          label
        );
      } else if (parsed.protocol !== 'https:') {
        addFinding(
          findings,
          'medium',
          'SERVICE_URL_SCHEME',
          'Unusual service URL scheme',
          `The service URL uses "${parsed.protocol}".`,
          'Confirm that this protocol is expected for this service type.',
          label
        );
      }
      if (parsed.username || parsed.password) {
        addFinding(
          findings,
          'high',
          'SERVICE_URL_CREDENTIALS',
          'Service URL contains embedded credentials',
          'The service URL contains a username or password component.',
          'Remove embedded credentials and use an approved authentication method.',
          label
        );
      }
      if (isLoopbackOrWildcard(parsed.hostname)) {
        addFinding(
          findings,
          'medium',
          'SERVICE_URL_LOOPBACK',
          'Web service points to loopback or wildcard address',
          `The URL host is "${parsed.hostname}".`,
          'Confirm that the endpoint is intended to be local to the workstation.',
          label
        );
      }
    } catch {
      addFinding(
        findings,
        'medium',
        'SERVICE_URL_INVALID',
        'Service URL is malformed',
        'The service URL could not be parsed.',
        'Check the URL syntax and confirm that the target is correct.',
        label
      );
    }
  }
  function checkMessageServers(servers, findings) {
    for (const server of servers) {
      const label = server.name || server.uuid || 'Unnamed message server';
      if (!server.name) {
        addFinding(
          findings,
          'low',
          'MS_NAME_MISSING',
          'Message server has no name',
          'A message server entry has no name attribute.',
          'Add a meaningful label to help administrators recognize the server.',
          label
        );
      }
      if (!server.uuid) {
        addFinding(
          findings,
          'medium',
          'MS_UUID_MISSING',
          'Message server UUID is missing',
          'A message server entry has no UUID.',
          'Verify the entry against the expected SAP landscape format.',
          label
        );
      }
      if (!server.server && !server.attributes.host) {
        addFinding(
          findings,
          'medium',
          'MS_HOST_MISSING',
          'Message server host is missing',
          'No server or host attribute was found on this message server entry.',
          'Verify that the message server definition contains its required target.',
          label
        );
      }
      if (server.port) {
        checkPort(server.port, label, findings, 'message server');
      }
    }
  }
  function checkRouters(routers, findings) {
    for (const router of routers) {
      const label = router.name || router.uuid || 'Unnamed router';
      const value = findAttribute(router.attributes, [
        'router',
        'routerstring',
        'string',
        'server'
      ]);
      if (!router.uuid) {
        addFinding(
          findings,
          'low',
          'ROUTER_UUID_MISSING',
          'Router UUID is missing',
          'A router entry has no UUID.',
          'Verify whether this is valid for the target landscape format.',
          label
        );
      }
      if (!value && !router.server) {
        addFinding(
          findings,
          'low',
          'ROUTER_TARGET_MISSING',
          'Router target not found',
          'The router entry does not contain an obvious router string or server target.',
          'Review the full router element and its expected attributes.',
          label
        );
      }
      if (value) {
        checkRouterString(value, label, findings);
      }
    }
  }
  function checkRouterString(value, label, findings) {
    const routerString = String(value).trim();
    if (!routerString) return;
    if (/\/W\/[^/]+/i.test(routerString)) {
      addFinding(
        findings,
        'high',
        'SAPROUTER_PASSWORD',
        'SAProuter string appears to contain a password',
        'The router string contains a /W/ segment followed by a value, which can represent router-password data.',
        'Check whether the string contains a real router password. Avoid distributing secrets in landscape files; rotate exposed credentials if necessary.',
        label
      );
    }
    if (!/^\/H\//i.test(routerString) && !/^[a-z][a-z0-9+.-]*:\/\//i.test(routerString)) {
      addFinding(
        findings,
        'low',
        'SAPROUTER_FORMAT_UNUSUAL',
        'Router string has an atypical format',
        'The router string does not begin with the common /H/ SAProuter syntax.',
        'Verify the syntax with the SAP network administrator. It may be valid in your environment.',
        label
      );
    }
    if (/[\r\n]/.test(routerString)) {
      addFinding(
        findings,
        'medium',
        'SAPROUTER_NEWLINE',
        'Router string contains a line break',
        'The router string contains line-break characters.',
        'Review the value for accidental formatting or malformed input.',
        label
      );
    }
  }
  function checkPort(port, label, findings, kind) {
    const value = String(port).trim();
    if (!/^\d+$/.test(value)) {
      addFinding(
        findings,
        'medium',
        'PORT_INVALID',
        'Port value is not numeric',
        `The ${kind} port is "${value}".`,
        'Verify that the port is correctly specified.',
        label
      );
      return;
    }
    const number = Number(value);
    if (number < 1 || number > 65535) {
      addFinding(
        findings,
        'medium',
        'PORT_OUT_OF_RANGE',
        'Port is outside the valid TCP/UDP port range',
        `The port value is ${number}.`,
        'Use a valid port number from 1 to 65535.',
        label
      );
    } else if (number < 1024) {
      addFinding(
        findings,
        'low',
        'PORT_PRIVILEGED',
        'Privileged port configured',
        `Port ${number} is in the well-known port range.`,
        'Confirm that this is intentional and approved for the service.',
        label
      );
    }
  }
  function checkDuplicateIds(items, type, findings) {
    const seen = new Map();
    for (const item of items) {
      if (!item.uuid) continue;
      const uuid = item.uuid.toLowerCase();
      if (seen.has(uuid)) {
        addFinding(
          findings,
          'medium',
          'DUPLICATE_UUID',
          `Duplicate ${type} UUID`,
          `UUID "${item.uuid}" appears more than once.`,
          'Check whether the duplicate entries should share an identifier.',
          item.name || item.uuid
        );
      } else {
        seen.set(uuid, item.name || item.uuid);
      }
    }
  }
  function checkDuplicateNames(services, findings) {
    const seen = new Map();
    for (const service of services) {
      if (!service.name) continue;
      const key = service.name.trim().toLowerCase();
      if (seen.has(key)) {
        addFinding(
          findings,
          'low',
          'DUPLICATE_SERVICE_NAME',
          'Duplicate service name',
          `The name "${service.name}" is used by multiple service entries.`,
          'Check that users can distinguish these connections clearly.',
          service.name
        );
      } else {
        seen.set(key, true);
      }
    }
  }
  function checkDuplicateEndpoints(services, findings) {
    const seen = new Map();
    for (const service of services) {
      const target = (service.server || service.group || '').trim().toLowerCase();
      const sid = service.systemId.trim().toLowerCase();
      const type = service.type.trim().toLowerCase();
      if (!target || !sid) continue;
      const key = `${type}|${sid}|${target}`;
      if (seen.has(key)) {
        addFinding(
          findings,
          'low',
          'DUPLICATE_ENDPOINT',
          'Multiple services use the same apparent endpoint',
          `Several services use system ID "${service.systemId}" and target "${target}".`,
          'Confirm whether the entries are intentional aliases or accidental duplicates.',
          service.name || target
        );
      } else {
        seen.set(key, true);
      }
    }
  }
  function checkRouterReferences(services, routers, findings) {
    if (routers.length === 0) return;
    const ids = new Set(
      routers.filter(router => router.uuid).map(router => router.uuid.toLowerCase())
    );
    for (const service of services) {
      if (!service.routerId) continue;
      if (!ids.has(service.routerId.toLowerCase())) {
        addFinding(
          findings,
          'medium',
          'ROUTER_REFERENCE_UNRESOLVED',
          'Service references an unlisted router',
          `The router reference "${service.routerId}" was not found among the Router elements in this file.`,
          'Check whether the router is defined in another included file. Includes are not fetched by this analyzer.',
          service.name || service.uuid
        );
      }
    }
  }
  function checkWorkspaceReferences(doc, services, findings) {
    const serviceIds = new Set(
      services.filter(service => service.uuid).map(service => service.uuid.toLowerCase())
    );
    const references = [];
    for (const element of elements(doc, 'Item')) {
      const ref = findAttribute(element, [
        'serviceid',
        'serviceuuid',
        'service',
        'uuid'
      ]);
      if (ref) references.push({ ref, name: attr(element, 'name') });
    }
    for (const reference of references) {
      if (
        /^[{(]?[0-9a-f-]{16,}[)}]?$/i.test(reference.ref) &&
        !serviceIds.has(reference.ref.replace(/[{}()]/g, '').toLowerCase())
      ) {
        addFinding(
          findings,
          'low',
          'WORKSPACE_REFERENCE_UNRESOLVED',
          'Workspace item may reference a missing service',
          `The item reference "${reference.ref}" was not matched to a Service UUID in this file.`,
          'Check whether the service exists in another landscape include. This is a heuristic because workspace formats vary.',
          reference.name || reference.ref
        );
      }
    }
  }
  function isLoopbackOrWildcard(host) {
    const value = String(host || '').trim().toLowerCase();
    return value === 'localhost' ||
      value === '0.0.0.0' ||
      value === '::' ||
      value === '::1' ||
      value === '127.0.0.1' ||
      value.startsWith('127.');
  }
  function addFinding(findings, severity, code, title, details, recommendation, target = '') {
    findings.push({
      severity,
      code,
      title,
      details,
      recommendation,
      target: String(target || '')
    });
  }
  function countSeverities(findings) {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    for (const finding of findings) {
      if (counts[finding.severity] !== undefined) {
        counts[finding.severity]++;
      }
    }
    return counts;
  }
  function renderReport(report) {
    const counts = countSeverities(report.findings);
    const source = report.source;
    results.innerHTML = `
      <div class="sub-result">
        <h3>Landscape overview</h3>
        <div class="grid">
          ${statCard(report.summary.services, 'Services')}
          ${statCard(report.summary.messageServers, 'Message servers')}
          ${statCard(report.summary.routers, 'Routers')}
          ${statCard(report.summary.includes, 'Includes')}
          ${statCard(report.summary.workspaces, 'Workspaces')}
          ${statCard(report.findings.length, 'Findings')}
        </div>
        <div class="notice">
          <strong>Source:</strong> ${escapeHtml(source.rootElement)}
          ${source.version ? ` · <strong>Version:</strong> ${escapeHtml(source.version)}` : ''}
          ${source.updated ? ` · <strong>Updated:</strong> ${escapeHtml(source.updated)}` : ''}
          ${source.generator ? `<br><strong>Generator:</strong> ${escapeHtml(source.generator)}` : ''}
        </div>
        <h3>Finding summary</h3>
        <div class="grid">
          ${statCard(counts.high + counts.critical, 'High priority')}
          ${statCard(counts.medium, 'Medium priority')}
          ${statCard(counts.low, 'Low priority')}
        </div>
        ${renderFindings(report.findings)}
        ${renderServices(report.services)}
        ${renderDefinitions('Message servers', report.messageServers)}
        ${renderDefinitions('Routers', report.routers)}
        ${renderIncludes(report.includes)}
        ${renderWorkspaces(report.workspaces)}
      </div>
    `;
  }
  function statCard(value, label) {
    return `
      <div class="stat">
        <strong>${escapeHtml(String(value))}</strong>
        <span>${escapeHtml(label)}</span>
      </div>
    `;
  }
  function renderFindings(findings) {
    if (findings.length === 0) {
      return `
        <div class="status ok">
          No findings were detected by the current checks.
          This does not prove that the landscape is secure or fully valid.
        </div>
      `;
    }
    const sorted = [...findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return order[a.severity] - order[b.severity];
    });
    return `
      <h3>Findings (${findings.length})</h3>
      <div class="tool-toolbar">
        <label for="sapLandscapeSeverity">
          Filter severity
        </label>
        <select id="sapLandscapeSeverity">
          <option value="all">All findings</option>
          <option value="high">High priority</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>
      <div id="sapLandscapeFindingList">
        ${sorted.map(finding => renderFinding(finding)).join('')}
      </div>
    `;
  }
  function renderFinding(finding) {
    const severityClass =
      finding.severity === 'high' || finding.severity === 'critical'
        ? 'danger'
        : finding.severity === 'medium'
          ? 'warn'
          : '';
    return `
      <div
        class="status ${severityClass} sap-landscape-finding"
        data-severity="${escapeHtml(finding.severity)}"
        style="border:1px solid var(--line); margin:10px 0;"
      >
        <div class="row">
          <strong>${escapeHtml(finding.title)}</strong>
          <span class="pill">${escapeHtml(finding.severity.toUpperCase())}</span>
          <span class="small">${escapeHtml(finding.code)}</span>
        </div>
        ${finding.target ? `<p><strong>Target:</strong> <code>${escapeHtml(finding.target)}</code></p>` : ''}
        <p>${escapeHtml(finding.details)}</p>
        <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
      </div>
    `;
  }
  results.addEventListener('change', event => {
    if (event.target.id !== 'sapLandscapeSeverity') return;
    const filter = event.target.value;
    const cards = results.querySelectorAll('.sap-landscape-finding');
    for (const card of cards) {
      card.hidden = filter !== 'all' && card.dataset.severity !== filter;
    }
  });
  function renderServices(services) {
    if (!services.length) return '';
    return `
      <h3>Services</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>System ID</th>
              <th>Client</th>
              <th>Server / group</th>
              <th>SNC option</th>
              <th>SNC name</th>
            </tr>
          </thead>
          <tbody>
            ${services.map(service => `
              <tr>
                <td>${escapeHtml(service.name || '—')}</td>
                <td>${escapeHtml(service.type || '—')}</td>
                <td>${escapeHtml(service.systemId || '—')}</td>
                <td>${escapeHtml(service.client || '—')}</td>
                <td>${escapeHtml(service.server || service.group || '—')}</td>
                <td>${escapeHtml(service.sncEnabled || '—')}</td>
                <td>${escapeHtml(service.sncName || '—')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
  function renderDefinitions(title, items) {
    if (!items.length) return '';
    return `
      <h3>${escapeHtml(title)}</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>UUID</th>
              <th>Server / target</th>
              <th>Port</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(item => `
              <tr>
                <td>${escapeHtml(item.name || '—')}</td>
                <td><code>${escapeHtml(item.uuid || '—')}</code></td>
                <td>${escapeHtml(item.server || item.url || '—')}</td>
                <td>${escapeHtml(item.port || '—')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
  function renderIncludes(includes) {
    if (!includes.length) return '';
    return `
      <h3>Landscape includes</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>URL / path</th>
              <th>Index</th>
              <th>Assessment</th>
            </tr>
          </thead>
          <tbody>
            ${includes.map(include => {
              const url = include.url || '';
              let assessment = 'Review target and permissions';
              if (/^https:\/\//i.test(url)) {
                assessment = 'HTTPS reference; not fetched';
              } else if (/^http:\/\//i.test(url)) {
                assessment = 'Plain HTTP; review security';
              } else if (/^file:\/\//i.test(url) || /^\\\\/.test(url)) {
                assessment = 'Local or network path; review permissions';
              }
              return `
                <tr>
                  <td><code>${escapeHtml(url || '—')}</code></td>
                  <td>${escapeHtml(include.attributes.index || '—')}</td>
                  <td>${escapeHtml(assessment)}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
  function renderWorkspaces(workspaces) {
    if (!workspaces.length) return '';
    return `
      <h3>Workspaces</h3>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>UUID</th>
            </tr>
          </thead>
          <tbody>
            ${workspaces.map(workspace => `
              <tr>
                <td>${escapeHtml(workspace.name || '—')}</td>
                <td><code>${escapeHtml(workspace.uuid || '—')}</code></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
  function showStatus(message, type = 'ok') {
    const cssClass = type === 'danger'
      ? 'danger'
      : type === 'warn'
        ? 'warn'
        : 'ok';
    status.innerHTML = `
      <div class="status ${cssClass}" role="status">
        ${escapeHtml(message)}
      </div>
    `;
  }
  function createTextReport(report) {
    const lines = [
      'SAP GUI Landscape Analyzer',
      `Analyzed at: ${report.analyzedAt}`,
      `Root: ${report.source.rootElement}`,
      `Version: ${report.source.version || '(not specified)'}`,
      '',
      'SUMMARY',
      `Services: ${report.summary.services}`,
      `Message servers: ${report.summary.messageServers}`,
      `Routers: ${report.summary.routers}`,
      `Includes: ${report.summary.includes}`,
      `Workspaces: ${report.summary.workspaces}`,
      `Findings: ${report.summary.findings}`,
      '',
      'FINDINGS'
    ];
    for (const finding of report.findings) {
      lines.push(
        `[${finding.severity.toUpperCase()}] ${finding.code}: ${finding.title}`,
        finding.target ? `Target: ${finding.target}` : '',
        finding.details,
        `Recommendation: ${finding.recommendation}`,
        ''
      );
    }
    lines.push(
      '',
      'Note: This report contains heuristic findings and is not a complete SAP security validation.'
    );
    return lines.filter(line => line !== undefined).join('\n');
  }
  function elements(doc, wantedName) {
    return Array.from(doc.getElementsByTagName('*')).filter(
      element => localName(element).toLowerCase() === wantedName.toLowerCase()
    );
  }
  function localName(element) {
    return element.localName || element.nodeName.split(':').pop();
  }
  function attr(element, name) {
    const wanted = name.toLowerCase();
    for (const attribute of Array.from(element.attributes || [])) {
      if (attribute.name.toLowerCase() === wanted) {
        return attribute.value.trim();
      }
    }
    return '';
  }
  function findAttribute(attributes, names) {
    for (const name of names) {
      const key = Object.keys(attributes).find(
        attribute => attribute.toLowerCase() === name.toLowerCase()
      );
      if (key && String(attributes[key]).trim()) {
        return String(attributes[key]).trim();
      }
    }
    return '';
  }
  function createExample() {
    return `<?xml version="1.0" encoding="UTF-8"?>
<Landscape updated="2026-01-01T12:00:00Z" version="1" generator="SAP GUI example">
  <Workspaces>
    <Workspace uuid="00000000-0000-0000-0000-000000000001" name="Local"/>
  </Workspaces>
  <Includes>
    <Include url="http://config.example.invalid/SAPUILandscapeGlobal.xml" index="0"/>
  </Includes>
  <Messageservers>
    <Messageserver
      uuid="00000000-0000-0000-0000-000000000010"
      name="Corporate Message Server"
      server="msg.example.invalid"
      port="3600"/>
  </Messageservers>
  <Routers>
    <Router
      uuid="00000000-0000-0000-0000-000000000020"
      name="Corporate Router"
      router="/H/router.example.invalid/S/3299"/>
  </Routers>
  <Services>
    <Service
      uuid="00000000-0000-0000-0000-000000000030"
      name="PRD - Production"
      type="SAPGUI"
      systemid="PRD"
      client="100"
      server="sapprd.example.invalid"
      sncop="0"/>
    <Service
      uuid="00000000-0000-0000-0000-000000000031"
      name="Web Launchpad"
      type="FIORI"
      url="http://fiori.example.invalid:8000/"
      client="100"/>
    <Service
      uuid="00000000-0000-0000-0000-000000000032"
      name="Development"
      type="SAPGUI"
      systemid="DEV"
      client="100"
      server="sapdev.example.invalid"
      sncop="1"
      sncname="p:CN=SAPDEV"/>
  </Services>
</Landscape>`;
  }
}
