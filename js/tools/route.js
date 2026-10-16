import { $, escapeHtml, downloadText, enableToolDragging} from '../utils.js';
export const metadata = {
  id: 'route',
  title: 'Route Calculator & Simulator',
  description: 'Calculate longest-prefix routing decisions and analyze routing tables locally',
  path: '/#route'
};
export function renderRoute(app) {
  app.innerHTML = `
    <div class="card tool-window" id="routeWindow">
      <div class="tool-window-header" id="routeDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>Route Calculator & Simulator</strong>
      </div>
      <div class="route-intro">
        <div>
          <strong>Which route actually wins?</strong>
          <div class="small">
            Test a destination against a routing table using longest-prefix
            matching and transparent tie-breaking.
          </div>
        </div>
      </div>
      <div class="route-tabs" role="tablist" aria-label="Route tool modes">
        <button
          type="button"
          class="route-tab active"
          id="routeTabDestination"
          role="tab"
          aria-selected="true"
        >
          Destination
        </button>
        <button
          type="button"
          class="route-tab"
          id="routeTabSimulator"
          role="tab"
          aria-selected="false"
        >
          Routing Simulator
        </button>
        <button
          type="button"
          class="route-tab"
          id="routeTabAnalyze"
          role="tab"
          aria-selected="false"
        >
          Analyze Table
        </button>
      </div>
      <section id="routeDestinationMode">
        <div class="tool-section">
          <label for="routeDestination">
            Destination
          </label>
          <input
            id="routeDestination"
            type="text"
            spellcheck="false"
            autocomplete="off"
            placeholder="10.20.30.45 or 2001:db8:1234::42"
          >
        </div>
        <div class="route-selection-options">
          <div>
            <label for="routeProfile">
              Route selection profile
            </label>
            <select id="routeProfile">
              <option value="lpm">Pure longest-prefix match</option>
              <option value="preference">Longest prefix → preference → metric</option>
              <option value="metric">Longest prefix → metric</option>
            </select>
          </div>
          <div class="route-profile-note" id="routeProfileNote">
            Longest prefix wins. Equal-prefix routes remain tied unless
            preference or metric is available.
          </div>
        </div>
        <div class="tool-section">
          <label for="routeTableInput">
            Routing table
          </label>
          <textarea
            id="routeTableInput"
            rows="12"
            spellcheck="false"
            placeholder="Destination       Next Hop        Interface   Metric   Type
0.0.0.0/0          192.168.1.1     eth0        100      static
10.0.0.0/8         10.0.0.1        eth1        10       static
10.20.0.0/16       10.20.0.1       eth2        20       static
10.20.30.0/24      10.20.30.1      eth3        50       static
10.20.30.32/27     10.20.30.33     eth4        5        static"
          ></textarea>
          <div class="tool-toolbar">
            <button class="btn primary" id="routeCalculate">
              Calculate Route
            </button>
            <button class="btn" id="routeLoadExample">
              Load example
            </button>
            <button class="btn" id="routeClear">
              Clear
            </button>
          </div>
        </div>
        <div id="routeDestinationStatus"></div>
        <div id="routeDestinationResult"></div>
      </section>
      <section id="routeSimulatorMode" hidden>
        <div class="tool-section">
          <label for="routeSimulatorTable">
            Routing table
          </label>
          <textarea
            id="routeSimulatorTable"
            rows="12"
            spellcheck="false"
            placeholder="Paste a normalized routing table or supported router output here..."
          ></textarea>
        </div>
        <div class="route-simulator-options">
          <div>
            <label for="routeSimulatorProfile">
              Route selection profile
            </label>
            <select id="routeSimulatorProfile">
              <option value="lpm">Pure longest-prefix match</option>
              <option value="preference">Longest prefix → preference → metric</option>
              <option value="metric">Longest prefix → metric</option>
            </select>
          </div>
          <div>
            <label for="routeSimulatorFormat">
              Input format
            </label>
            <select id="routeSimulatorFormat">
              <option value="auto">Auto detect</option>
              <option value="normalized">Normalized table</option>
              <option value="linux">Linux ip route</option>
              <option value="windows">Windows route print</option>
              <option value="cisco">Cisco show ip route</option>
              <option value="juniper">Juniper show route</option>
            </select>
          </div>
        </div>
        <div class="tool-section">
          <label for="routeDestinations">
            Destinations to test
          </label>
          <textarea
            id="routeDestinations"
            rows="7"
            spellcheck="false"
            placeholder=
"10.20.30.45
10.20.30.100
10.20.50.12
10.50.1.8
8.8.8.8"
          ></textarea>
          <div class="tool-toolbar">
            <button class="btn primary" id="routeRunSimulator">
              Run Simulation
            </button>
            <button class="btn" id="routeLoadSimulatorExample">
              Load example
            </button>
          </div>
        </div>
        <div id="routeSimulatorStatus"></div>
        <div id="routeSimulatorResult"></div>
      </section>
      <section id="routeAnalyzeMode" hidden>
        <div class="tool-section">
          <label for="routeAnalyzeTable">
            Routing table
          </label>
          <textarea
            id="routeAnalyzeTable"
            rows="14"
            spellcheck="false"
            placeholder="Paste a routing table here..."
          ></textarea>
          <div class="route-analyze-options">
            <div>
              <label for="routeAnalyzeFormat">
                Input format
              </label>
              <select id="routeAnalyzeFormat">
                <option value="auto">Auto detect</option>
                <option value="normalized">Normalized table</option>
                <option value="linux">Linux ip route</option>
                <option value="windows">Windows route print</option>
                <option value="cisco">Cisco show ip route</option>
                <option value="juniper">Juniper show route</option>
              </select>
            </div>
          </div>
          <div class="tool-toolbar">
            <button class="btn primary" id="routeAnalyze">
              Analyze Routing Table
            </button>
            <button class="btn" id="routeLoadAnalyzeExample">
              Load example
            </button>
          </div>
        </div>
        <div id="routeAnalyzeStatus"></div>
        <div id="routeAnalyzeResult"></div>
      </section>
      <div class="route-footer-actions">
        <button class="btn" id="routeExportJson">
          Export analysis JSON
        </button>
        <button class="btn" id="routeExportText">
          Export analysis text
        </button>
      </div>
    </div>
  `;
  enableToolDragging(
    $('#routeWindow'),
    $('#routeDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
  const state = {
    lastAnalysis: null
  };
  setupTabs();
  setupEvents();
  function setupTabs() {
    $('#routeTabDestination').addEventListener('click', () => {
      setMode('destination');
    });
    $('#routeTabSimulator').addEventListener('click', () => {
      setMode('simulator');
    });
    $('#routeTabAnalyze').addEventListener('click', () => {
      setMode('analyze');
    });
  }
  function setMode(mode) {
    const destination = mode === 'destination';
    const simulator = mode === 'simulator';
    const analyze = mode === 'analyze';
    $('#routeDestinationMode').hidden = !destination;
    $('#routeSimulatorMode').hidden = !simulator;
    $('#routeAnalyzeMode').hidden = !analyze;
    setTabState('#routeTabDestination', destination);
    setTabState('#routeTabSimulator', simulator);
    setTabState('#routeTabAnalyze', analyze);
  }
  function setTabState(selector, active) {
    const button = $(selector);
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
  }
  function setupEvents() {
    $('#routeCalculate').addEventListener('click', calculateDestination);
    $('#routeLoadExample').addEventListener('click', () => {
      const example = createExample();
      $('#routeDestination').value = example.destination;
      $('#routeTableInput').value = example.table;
      calculateDestination();
    });
    $('#routeClear').addEventListener('click', clearDestination);
    $('#routeRunSimulator').addEventListener(
      'click',
      runSimulator
    );
    $('#routeLoadSimulatorExample').addEventListener(
      'click',
      () => {
        const example = createExample();
        $('#routeSimulatorTable').value = example.table;
        $('#routeDestinations').value = example.destinations.join('\n');
        runSimulator();
      }
    );
    $('#routeAnalyze').addEventListener(
      'click',
      analyzeTable
    );
    $('#routeLoadAnalyzeExample').addEventListener(
      'click',
      () => {
        $('#routeAnalyzeTable').value = createExample().analysisTable;
        analyzeTable();
      }
    );
    $('#routeProfile').addEventListener('change', updateProfileNote);
    $('#routeExportJson').addEventListener('click', exportJson);
    $('#routeExportText').addEventListener('click', exportText);
  }
  function updateProfileNote() {
    const profile = $('#routeProfile').value;
    const notes = {
      lpm:
        'Longest prefix wins. Equal-prefix routes remain tied unless the input contains a single best candidate.',
      preference:
        'Longest prefix wins first. For equal prefixes, lower route preference wins, then lower metric.',
      metric:
        'Longest prefix wins first. For equal prefixes, lower metric wins.'
    };
    $('#routeProfileNote').textContent =
      notes[profile] || notes.lpm;
  }
  function calculateDestination() {
    const destinationText = $('#routeDestination').value.trim();
    const tableText = $('#routeTableInput').value.trim();
    if (!destinationText) {
      showError(
        '#routeDestinationStatus',
        'Enter a destination address first.'
      );
      return;
    }
    if (!tableText) {
      showError(
        '#routeDestinationStatus',
        'Enter or paste a routing table first.'
      );
      return;
    }
    try {
      const destination = parseIpAddress(destinationText);
      const parsed = parseRoutingTable(
        tableText,
        'auto'
      );
      if (!parsed.routes.length) {
        throw new Error(
          'No valid routes were found in the supplied routing table.'
        );
      }
      const profile = $('#routeProfile').value;
      const decision = selectRoute(
        destination,
        parsed.routes,
        profile
      );
      state.lastAnalysis = {
        kind: 'destination',
        destination: destinationText,
        profile,
        detectedFormat: parsed.format,
        routes: parsed.routes,
        decision
      };
      $('#routeDestinationStatus').innerHTML = '';
      $('#routeDestinationResult').innerHTML =
        renderDestinationResult(
          destination,
          decision,
          profile,
          parsed
        );
    } catch (error) {
      showError(
        '#routeDestinationStatus',
        error.message
      );
    }
  }
  function runSimulator() {
    const tableText = $('#routeSimulatorTable').value.trim();
    const destinationsText =
      $('#routeDestinations').value.trim();
    if (!tableText) {
      showError(
        '#routeSimulatorStatus',
        'Enter or paste a routing table first.'
      );
      return;
    }
    if (!destinationsText) {
      showError(
        '#routeSimulatorStatus',
        'Enter at least one destination to test.'
      );
      return;
    }
    try {
      const parsed = parseRoutingTable(
        tableText,
        $('#routeSimulatorFormat').value
      );
      if (!parsed.routes.length) {
        throw new Error(
          'No valid routes were found in the supplied routing table.'
        );
      }
      const destinations = destinationsText
        .split(/\r?\n/)
        .map(value => value.trim())
        .filter(Boolean);
      const results = [];
      for (const value of destinations) {
        try {
          const destination = parseIpAddress(value);
          const decision = selectRoute(
            destination,
            parsed.routes,
            $('#routeSimulatorProfile').value
          );
          results.push({
            input: value,
            destination,
            decision
          });
        } catch (error) {
          results.push({
            input: value,
            error: error.message
          });
        }
      }
      state.lastAnalysis = {
        kind: 'simulator',
        profile: $('#routeSimulatorProfile').value,
        detectedFormat: parsed.format,
        routes: parsed.routes,
        results
      };
      $('#routeSimulatorStatus').innerHTML =
        `<div class="tool-status tool-status-success">
          Tested ${results.length} destination${results.length === 1 ? '' : 's'}.
        </div>`;
      $('#routeSimulatorResult').innerHTML =
        renderSimulatorResult(results);
    } catch (error) {
      showError(
        '#routeSimulatorStatus',
        error.message
      );
    }
  }
  function analyzeTable() {
    const text = $('#routeAnalyzeTable').value.trim();
    if (!text) {
      showError(
        '#routeAnalyzeStatus',
        'Enter or paste a routing table first.'
      );
      return;
    }
    try {
      const parsed = parseRoutingTable(
        text,
        $('#routeAnalyzeFormat').value
      );
      if (!parsed.routes.length) {
        throw new Error(
          'No valid routes were found in the supplied routing table.'
        );
      }
      const analysis = analyzeRoutingTable(
        parsed.routes
      );
      state.lastAnalysis = {
        kind: 'table-analysis',
        detectedFormat: parsed.format,
        routes: parsed.routes,
        analysis
      };
      $('#routeAnalyzeStatus').innerHTML =
        `<div class="tool-status tool-status-success">
          Analyzed ${parsed.routes.length} route${parsed.routes.length === 1 ? '' : 's'}.
          Detected format: ${escapeHtml(parsed.formatLabel)}.
        </div>`;
      $('#routeAnalyzeResult').innerHTML =
        renderTableAnalysis(
          parsed.routes,
          analysis
        );
    } catch (error) {
      showError(
        '#routeAnalyzeStatus',
        error.message
      );
    }
  }
  function clearDestination() {
    $('#routeDestination').value = '';
    $('#routeTableInput').value = '';
    $('#routeDestinationStatus').innerHTML = '';
    $('#routeDestinationResult').innerHTML = '';
    state.lastAnalysis = null;
  }
  function exportJson() {
    if (!state.lastAnalysis) {
      return;
    }
    downloadText(
      'route-analysis.json',
      JSON.stringify(
        serializeAnalysis(state.lastAnalysis),
        null,
        2
      ),
      'application/json;charset=utf-8'
    );
  }
  function exportText() {
    if (!state.lastAnalysis) {
      return;
    }
    downloadText(
      'route-analysis.txt',
      buildExportText(state.lastAnalysis),
      'text/plain;charset=utf-8'
    );
  }
  function parseRoutingTable(text, requestedFormat = 'auto') {
    const format =
      requestedFormat === 'auto'
        ? detectTableFormat(text)
        : requestedFormat;
    let routes = [];
    switch (format) {
      case 'linux':
        routes = parseLinuxRoutes(text);
        break;
      case 'windows':
        routes = parseWindowsRoutes(text);
        break;
      case 'cisco':
        routes = parseCiscoRoutes(text);
        break;
      case 'juniper':
        routes = parseJuniperRoutes(text);
        break;
      case 'normalized':
      default:
        routes = parseNormalizedRoutes(text);
        break;
    }
    return {
      format,
      formatLabel: formatLabel(format),
      routes
    };
  }
  function detectTableFormat(text) {
    const lower = text.toLowerCase();
    if (
      /\broute\s+print\b/i.test(text) ||
      /\bactive routes\b/i.test(text) ||
      /\bnetwork destination\b/i.test(text)
    ) {
      return 'windows';
    }
    if (
      /\bip route\b/i.test(text) ||
      /\bproto\s+(kernel|static|dhcp|boot|ra)\b/i.test(text) ||
      /\bvia\s+\S+\s+dev\s+\S+/i.test(text)
    ) {
      return 'linux';
    }
    if (
      /\bshow\s+ip\s+route\b/i.test(text) ||
      /^\s*[A-Z]\s+\S+\/\d+/m.test(text) ||
      /\bvia\s+\S+,\s*\S+/i.test(text)
    ) {
      return 'cisco';
    }
    if (
      /\bshow\s+route\b/i.test(text) ||
      /\bto\s+\S+\/\d+\s+via\b/i.test(text) ||
      /\bDirect\s+\S+/i.test(text)
    ) {
      return 'juniper';
    }
    return 'normalized';
  }
  function parseNormalizedRoutes(text) {
    const routes = [];
    const lines = text.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) {
        continue;
      }
      if (
        /^(destination|network|prefix)\b/i.test(line)
      ) {
        continue;
      }
      const tokens = splitRouteLine(line);
      if (!tokens.length) {
        continue;
      }
      const prefixToken = tokens.find(
        token => isCidr(token)
      );
      if (!prefixToken) {
        continue;
      }
      try {
        const route = createRoute({
          prefix: prefixToken,
          nextHop: findNextHop(tokens, prefixToken),
          interfaceName: findInterface(tokens, prefixToken),
          metric: findNumberAfter(tokens, prefixToken, [
            'metric',
            'cost'
          ]),
          preference: findNumberAfter(tokens, prefixToken, [
            'preference',
            'distance',
            'admin',
            'administrative'
          ]),
          type: findRouteType(tokens),
          source: rawLine
        });
        routes.push(route);
      } catch {      }
    }
    return routes;
  }
  function splitRouteLine(line) {
    if (line.includes('\t')) {
      return line
        .split(/\t+/)
        .map(value => value.trim())
        .filter(Boolean);
    }
    if (/\s{2,}/.test(line)) {
      return line
        .split(/\s{2,}/)
        .map(value => value.trim())
        .filter(Boolean);
    }
    return line
      .split(/\s+/)
      .map(value => value.trim())
      .filter(Boolean);
  }
  function findNextHop(tokens, prefix) {
    const index = tokens.indexOf(prefix);
    const explicitVia = tokens.findIndex(
      token => token.toLowerCase() === 'via'
    );
    if (
      explicitVia >= 0 &&
      tokens[explicitVia + 1]
    ) {
      return tokens[explicitVia + 1];
    }
    for (let i = index + 1; i < tokens.length; i++) {
      const token = tokens[i];
      if (
        token === '-' ||
        token === '*' ||
        isNumber(token) ||
        isInterfaceToken(token) ||
        isCidr(token) ||
        isIpAddressSafe(token)
      ) {
        if (isIpAddressSafe(token)) {
          return token;
        }
      }
    }
    return '';
  }
  function findInterface(tokens, prefix) {
    const index = tokens.indexOf(prefix);
    const devIndex = tokens.findIndex(
      token => token.toLowerCase() === 'dev'
    );
    if (
      devIndex >= 0 &&
      tokens[devIndex + 1]
    ) {
      return tokens[devIndex + 1];
    }
    const ifaceIndex = tokens.findIndex(
      token =>
        /^(interface|iface|if)$/i.test(token)
    );
    if (
      ifaceIndex >= 0 &&
      tokens[ifaceIndex + 1]
    ) {
      return tokens[ifaceIndex + 1];
    }
    for (let i = index + 1; i < tokens.length; i++) {
      const token = tokens[i];
      if (
        isInterfaceToken(token) &&
        !isNumber(token)
      ) {
        return token;
      }
    }
    return '';
  }
  function findNumberAfter(tokens, prefix, labels) {
    const prefixIndex = tokens.indexOf(prefix);
    for (
      let i = Math.max(0, prefixIndex);
      i < tokens.length - 1;
      i++
    ) {
      if (
        labels.includes(
          tokens[i].toLowerCase().replace(':', '')
        )
      ) {
        const value = Number(tokens[i + 1]);
        if (Number.isFinite(value)) {
          return value;
        }
      }
    }
    return null;
  }
  function findRouteType(tokens) {
    const known = [
      'static',
      'connected',
      'kernel',
      'dhcp',
      'ospf',
      'bgp',
      'rip',
      'eigrp',
      'isis',
      'local',
      'broadcast',
      'unreachable',
      'prohibit',
      'blackhole',
      'throw',
      'direct'
    ];
    for (const token of tokens) {
      const value = token.toLowerCase();
      if (known.includes(value)) {
        return value;
      }
    }
    return '';
  }
  function parseLinuxRoutes(text) {
    const routes = [];
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }
      const tokens = line.split(/\s+/);
      let prefix = tokens[0];
      if (prefix === 'default') {
        prefix = '0.0.0.0/0';
      }
      if (!isCidr(prefix)) {
        continue;
      }
      try {
        const route = createRoute({
          prefix,
          nextHop: valueAfter(tokens, 'via'),
          interfaceName: valueAfter(tokens, 'dev'),
          metric: numberAfter(tokens, 'metric'),
          preference: numberAfter(tokens, 'pref'),
          type:
            valueAfter(tokens, 'proto') ||
            findRouteType(tokens),
          source: rawLine
        });
        routes.push(route);
      } catch {   }
    }
    return routes;
  }
  function parseWindowsRoutes(text) {
    const routes = [];
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }
      const match = line.match(
        /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/
      );
      if (!match) {
        continue;
      }
      const [
        ,
        network,
        mask,
        gateway,
        interfaceName,
        metric
      ] = match;
      if (!isIPv4(network) || !isIPv4(mask)) {
        continue;
      }
      try {
        const prefixLength =
          ipv4MaskToPrefix(mask);
        routes.push(
          createRoute({
            prefix: `${network}/${prefixLength}`,
            nextHop: gateway,
            interfaceName,
            metric: Number(metric),
            type: 'windows',
            source: rawLine
          })
        );
      } catch {  }
    }
    return routes;
  }
  function parseCiscoRoutes(text) {
    const routes = [];
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }const match = line.match(
        /^([A-Za-z*]+)\s+(\S+\/\d+)(?:\s+\[(\d+)\/(\d+)\])?\s+(.*)$/
      );
      if (!match) {
        continue;
      }
      const [
        ,
        code,
        prefix,
        preference,
        metric,
        remainder
      ] = match;
      try {
        const viaMatch =
          remainder.match(/\bvia\s+(\S+)/i);
        const interfaceMatch =
          remainder.match(
            /,\s*(?:\S+\s*,\s*)?([A-Za-z][A-Za-z0-9./_-]*)$/
          );
        routes.push(
          createRoute({
            prefix,
            nextHop:
              viaMatch?.[1] ||
              '',
            interfaceName:
              interfaceMatch?.[1] ||
              '',
            preference:
              preference === undefined
                ? null
                : Number(preference),
            metric:
              metric === undefined
                ? null
                : Number(metric),
            type: ciscoCodeToType(code),
            source: rawLine
          })
        );
      } catch {  }
    }
    return routes;
  }
  function parseJuniperRoutes(text) {
    const routes = [];
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }
      const prefixMatch =
        line.match(
          /^(\S+\/\d+)\s+\*\[([^/]+)\/(\d+)\]/
        );
      if (prefixMatch) {
        const prefix = prefixMatch[1];
        const type = prefixMatch[2];
        const preference = Number(prefixMatch[3]);
        const viaMatch =
          line.match(/\bvia\s+(\S+)/i);
        const toMatch =
          line.match(/\bto\s+(\S+)/i);
        routes.push(
          createRoute({
            prefix,
            nextHop:
              viaMatch?.[1] ||
              toMatch?.[1] ||
              '',
            interfaceName:
              line.match(
                /\bvia\s+\S+\s+(\S+)/
              )?.[1] ||
              '',
            preference,
            type,
            source: rawLine
          })
        );
        continue;
      }
      const indentedMatch =
        line.match(
          /^>\s*(?:to\s+)?(\S+)(?:\s+via\s+(\S+))?/
        );
      if (indentedMatch && routes.length) {
        const last = routes[routes.length - 1];
        if (!last.nextHop) {
          last.nextHop = indentedMatch[1] || '';
        }
        if (
          !last.interfaceName &&
          indentedMatch[2]
        ) {
          last.interfaceName = indentedMatch[2];
        }
      }
    }
    return routes;
  }
  function createRoute(data) {
    const parsedPrefix =
      parsePrefix(data.prefix);
    return {
      id: createRouteId(),
      family: parsedPrefix.family,
      prefix: parsedPrefix.prefix,
      network: parsedPrefix.network,
      prefixLength: parsedPrefix.prefixLength,
      mask: parsedPrefix.mask,
      nextHop: data.nextHop || '',
      interfaceName: data.interfaceName || '',
      metric:
        Number.isFinite(data.metric)
          ? data.metric
          : null,
      preference:
        Number.isFinite(data.preference)
          ? data.preference
          : null,
      type: data.type || '',
      source: data.source || '',
      start: parsedPrefix.start,
      end: parsedPrefix.end,
      size: parsedPrefix.size
    };
  }
  function selectRoute(
    destination,
    routes,
    profile
  ) {
    const matched = routes
      .filter(route =>
        addressInRoute(destination, route)
      )
      .sort(compareRoutes(profile));
    const selected = matched.length
      ? matched[0]
      : null;
    const tied = selected
      ? matched.filter(
          route =>
            route.prefixLength ===
              selected.prefixLength &&
            sameTieBreakValues(
              route,
              selected,
              profile
            )
        )
      : [];
    const ecmp =
      tied.length > 1 &&
      tied.some(
        route =>
          route.nextHop !== selected.nextHop ||
          route.interfaceName !== selected.interfaceName
      );
    return {
      matched,
      selected,
      ecmp,
      tieCandidates: tied
    };
  }
  function compareRoutes(profile) {
    return (a, b) => {
      if (a.prefixLength !== b.prefixLength) {
        return b.prefixLength - a.prefixLength;
      }
      if (profile === 'preference') {
        const aPreference =
          a.preference ?? Number.MAX_SAFE_INTEGER;
        const bPreference =
          b.preference ?? Number.MAX_SAFE_INTEGER;
        if (aPreference !== bPreference) {
          return aPreference - bPreference;
        }
        const aMetric =
          a.metric ?? Number.MAX_SAFE_INTEGER;
        const bMetric =
          b.metric ?? Number.MAX_SAFE_INTEGER;
        if (aMetric !== bMetric) {
          return aMetric - bMetric;
        }
      }
      if (profile === 'metric') {
        const aMetric =
          a.metric ?? Number.MAX_SAFE_INTEGER;
        const bMetric =
          b.metric ?? Number.MAX_SAFE_INTEGER;
        if (aMetric !== bMetric) {
          return aMetric - bMetric;
        }
      }
      return a.id.localeCompare(b.id);
    };
  }
  function sameTieBreakValues(
    a,
    b,
    profile
  ) {
    if (profile === 'preference') {
      return (
        (a.preference ?? null) ===
          (b.preference ?? null) &&
        (a.metric ?? null) ===
          (b.metric ?? null)
      );
    }
    if (profile === 'metric') {
      return (
        (a.metric ?? null) ===
        (b.metric ?? null)
      );
    }
    return true;
  }
  function addressInRoute(destination, route) {
    if (destination.family !== route.family) {
      return false;
    }
    return (
      (destination.value & route.mask) ===
      route.start
    );
  }
  function analyzeRoutingTable(routes) {
    const duplicates = [];
    const overlaps = [];
    const shadowed = [];
    for (let i = 0; i < routes.length; i++) {
      for (let j = i + 1; j < routes.length; j++) {
        const a = routes[i];
        const b = routes[j];
        if (
          a.family !== b.family
        ) {
          continue;
        }
        if (
          a.prefix === b.prefix
        ) {
          duplicates.push({
            prefix: a.prefix,
            routes: [a, b]
          });
          continue;
        }
        if (
          rangesOverlap(a, b)
        ) {
          overlaps.push({
            broader:
              a.prefixLength <
              b.prefixLength
                ? a
                : b,
            narrower:
              a.prefixLength <
              b.prefixLength
                ? b
                : a
          });
        }
      }
    }
    const uniquePrefixes = uniqueByPrefix(routes);
    for (const route of uniquePrefixes) {
      const coveringRoutes =
        uniquePrefixes.filter(
          candidate =>
            candidate.family === route.family &&
            candidate.prefixLength > route.prefixLength &&
            rangeContains(
              candidate,
              route
            )
        );
      if (!coveringRoutes.length) {
        continue;
      }
      if (
        isCompletelyCovered(
          route,
          coveringRoutes
        )
      ) {
        shadowed.push({
          route,
          coveringRoutes
        });
      }
    }
    return {
      duplicates,
      overlaps,
      shadowed,
      hierarchy: buildPrefixHierarchy(routes)
    };
  }
  function isCompletelyCovered(
    target,
    coveringRoutes
  ) {
    const relevant = coveringRoutes
      .filter(route =>
        rangeContains(target, route)
      )
      .sort(compareRanges);
    if (!relevant.length) {
      return false;
    }
    let cursor = target.start;
    for (const route of relevant) {
      if (route.end < cursor) {
        continue;
      }
      if (route.start > cursor) {
        return false;
      }
      if (route.end >= cursor) {
        cursor = route.end + 1n;
      }
      if (cursor > target.end) {
        return true;
      }
    }
    return false;
  }
  function compareRanges(a, b) {
    if (a.start < b.start) {
      return -1;
    }
    if (a.start > b.start) {
      return 1;
    }
    return (
      b.prefixLength -
      a.prefixLength
    );
  }
  function rangesOverlap(a, b) {
    return (
      a.start <= b.end &&
      b.start <= a.end
    );
  }
  function rangeContains(
    broader,
    narrower
  ) {
    return (
      broader.family === narrower.family &&
      broader.start <= narrower.start &&
      broader.end >= narrower.end
    );
  }
  function buildPrefixHierarchy(routes) {
    const roots = [];
    const sorted = [...routes].sort(
      (a, b) =>
        a.prefixLength -
          b.prefixLength ||
        a.prefix.localeCompare(b.prefix)
    );
    const nodes = sorted.map(route => ({
      route,
      children: []
    }));
    for (const node of nodes) {
      let parent = null;
      for (const candidate of nodes) {
        if (candidate === node) {
          continue;
        }
        if (
          candidate.route.family !==
          node.route.family
        ) {
          continue;
        }
        if (
          candidate.route.prefixLength >=
          node.route.prefixLength
        ) {
          continue;
        }
        if (
          rangeContains(
            candidate.route,
            node.route
          )
        ) {
          if (
            !parent ||
            candidate.route.prefixLength >
              parent.route.prefixLength
          ) {
            parent = candidate;
          }
        }
      }
      if (parent) {
        parent.children.push(node);
      } else {
        roots.push(node);
      }
    }
    return roots;
  }
  function uniqueByPrefix(routes) {
    const map = new Map();
    for (const route of routes) {
      if (!map.has(route.prefix)) {
        map.set(route.prefix, route);
      }
    }
    return [...map.values()];
  }
  function renderDestinationResult(
    destination,
    decision,
    profile,
    parsed
  ) {
    if (!decision.selected) {
      return `
        <div class="route-result">
          <div class="route-empty">
            <strong>No matching route</strong>
            <span>
              ${escapeHtml(
                formatIp(destination)
              )}
              is not covered by the supplied routing table.
            </span>
          </div>
        </div>
      `;
    }
    const selected = decision.selected;
    return `
      <div class="route-result">
        <div class="route-result-heading">
          <div>
            <div class="small">Routing decision for</div>
            <h3>${escapeHtml(
              formatIp(destination)
            )}</h3>
          </div>
          <span class="route-family-badge">
            IPv${destination.family}
          </span>
        </div>
        <section class="route-result-section">
          <h4>Matched routes</h4>
          <div class="route-match-list">
            ${decision.matched
              .map(
                (route, index) =>
                  renderMatchedRoute(
                    route,
                    destination,
                    index === 0
                  )
              )
              .join('')}
          </div>
        </section>
        <section class="route-selected">
          <div class="route-selected-heading">
            <div class="small">Selected route</div>
            <strong>${escapeHtml(
              selected.prefix
            )}</strong>
          </div>
          <div class="route-selected-grid">
            <div>
              <span>Destination</span>
              <strong>${escapeHtml(
                formatIp(destination)
              )}</strong>
            </div>
            <div>
              <span>Network</span>
              <strong>${escapeHtml(
                selected.network
              )}</strong>
            </div>
            <div>
              <span>Next hop</span>
              <strong>${escapeHtml(
                selected.nextHop || 'on-link'
              )}</strong>
            </div>
            <div>
              <span>Interface</span>
              <strong>${escapeHtml(
                selected.interfaceName || '-'
              )}</strong>
            </div>
            <div>
              <span>Prefix</span>
              <strong>/${selected.prefixLength}</strong>
            </div>
            <div>
              <span>Matched prefix bits</span>
              <strong>${selected.prefixLength}</strong>
            </div>
            <div>
              <span>Preference</span>
              <strong>${formatNumber(
                selected.preference
              )}</strong>
            </div>
            <div>
              <span>Metric</span>
              <strong>${formatNumber(
                selected.metric
              )}</strong>
            </div>
          </div>
        </section>
        <section class="route-why">
          <h4>Why did this route win?</h4>
          ${renderWhyExplanation(
            decision,
            profile
          )}
        </section>
        ${
          decision.ecmp
            ? `
              <div class="route-warning">
                <strong>ECMP / equal candidates</strong>
                <span>
                  Multiple routes remain tied after the configured
                  comparison. A real device may load-share between
                  them depending on platform behavior.
                </span>
              </div>
            `
            : ''
        }
        <section class="route-command-section">
          <h4>Generate a test command</h4>
          ${renderTestCommands(
            destination
          )}
        </section>
        <div class="route-raw-info">
          Detected input format:
          <strong>${escapeHtml(
            parsed.formatLabel
          )}</strong>
        </div>
      </div>
    `;
  }
  function renderMatchedRoute(
    route,
    destination,
    selected
  ) {
    const relation = selected
      ? 'selected'
      : 'matched';
    return `
      <div class="route-match ${relation}">
        <div class="route-match-icon">
          ${selected ? '✓' : '•'}
        </div>
        <div class="route-match-main">
          <strong>${escapeHtml(
            route.prefix
          )}</strong>
          <span>
            ${escapeHtml(
              route.nextHop || 'on-link'
            )}
          </span>
          <span>
            ${escapeHtml(
              route.interfaceName || '-'
            )}
          </span>
        </div>
        <div class="route-match-meta">
          <span>/${route.prefixLength}</span>
          <span>
            metric ${formatNumber(route.metric)}
          </span>
          ${
            route.preference !== null
              ? `<span>
                  pref ${route.preference}
                </span>`
              : ''
          }
        </div>
      </div>
    `;
  }
  function renderWhyExplanation(
    decision,
    profile
  ) {
    const selected = decision.selected;
    if (!selected) {
      return `
        <div class="route-explanation">
          <div>
            <strong>No route matched.</strong>
            The destination is outside every supplied prefix.
          </div>
        </div>
      `;
    }
    const explanations = [];
    if (decision.matched.length === 1) {
      explanations.push(
        `Only ${selected.prefix} contains the destination.`
      );
    } else {
      const moreSpecific =
        decision.matched
          .filter(
            route =>
              route.prefixLength <
              selected.prefixLength
          )
          .map(
            route =>
              `${route.prefix} is less specific than ${selected.prefix}`
          );
      explanations.push(
        `${selected.prefix} has the longest matching prefix (${selected.prefixLength} bits).`
      );
      for (const item of moreSpecific) {
        explanations.push(item);
      }
    }
    const samePrefix =
      decision.matched.filter(
        route =>
          route.prefixLength ===
          selected.prefixLength
      );
    if (samePrefix.length > 1) {
      if (profile === 'preference') {
        explanations.push(
          `Equal-prefix candidates are compared by route preference, then metric.`
        );
        if (
          selected.preference !== null
        ) {
          explanations.push(
            `Selected preference: ${selected.preference}.`
          );
        }
        if (
          selected.metric !== null
        ) {
          explanations.push(
            `Selected metric: ${selected.metric}.`
          );
        }
      } else if (profile === 'metric') {
        explanations.push(
          `Equal-prefix candidates are compared by metric.`
        );
      } else {
        explanations.push(
          `Equal-prefix candidates remain tied under pure longest-prefix matching.`
        );
      }
    }
    return `
      <div class="route-explanation">
        ${explanations
          .map(
            item => `
              <div class="route-explanation-item">
                <span>→</span>
                <span>${escapeHtml(item)}</span>
              </div>
            `
          )
          .join('')}
      </div>
    `;
  }
  function renderSimulatorResult(results) {
    return `
      <div class="route-simulation">
        <div class="route-simulation-summary">
          <strong>Simulation results</strong>
          <span>
            ${results.length}
            destination${results.length === 1 ? '' : 's'}
          </span>
        </div>
        <div class="table-wrap">
          <table class="route-simulation-table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Selected route</th>
                <th>Next hop</th>
                <th>Interface</th>
                <th>Prefix</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${results
                .map(result => {
                  if (result.error) {
                    return `
                      <tr>
                        <td>
                          ${escapeHtml(result.input)}
                        </td>
                        <td colspan="4">-</td>
                        <td>
                          <span class="route-badge danger">
                            ${escapeHtml(
                              result.error
                            )}
                          </span>
                        </td>
                      </tr>
                    `;
                  }
                  const selected =
                    result.decision.selected;
                  if (!selected) {
                    return `
                      <tr>
                        <td>
                          ${escapeHtml(
                            result.input
                          )}
                        </td>
                        <td colspan="4">No matching route</td>
                        <td>
                          <span class="route-badge warning">
                            Unrouted
                          </span>
                        </td>
                      </tr>
                    `;
                  }
                  return `
                    <tr>
                      <td>
                        <code>${escapeHtml(
                          result.input
                        )}</code>
                      </td>
                      <td>
                        <strong>${escapeHtml(
                          selected.prefix
                        )}</strong>
                      </td>
                      <td>
                        ${escapeHtml(
                          selected.nextHop ||
                            'on-link'
                        )}
                      </td>
                      <td>
                        ${escapeHtml(
                          selected.interfaceName ||
                            '-'
                        )}
                      </td>
                      <td>
                        /${selected.prefixLength}
                      </td>
                      <td>
                        <span class="route-badge success">
                          Selected
                        </span>
                      </td>
                    </tr>
                  `;
                })
                .join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
  function renderTableAnalysis(
    routes,
    analysis
  ) {
    return `
      <div class="route-analysis">
        <div class="route-analysis-stats">
          <div class="stat">
            <strong>${routes.length}</strong>
            <span>Routes</span>
          </div>
          <div class="stat">
            <strong>${analysis.duplicates.length}</strong>
            <span>Duplicates</span>
          </div>
          <div class="stat">
            <strong>${analysis.overlaps.length}</strong>
            <span>Overlaps</span>
          </div>
          <div class="stat">
            <strong>${analysis.shadowed.length}</strong>
            <span>Shadowed</span>
          </div>
        </div>
        ${renderDuplicateSection(
          analysis.duplicates
        )}
        ${renderShadowedSection(
          analysis.shadowed
        )}
        ${renderOverlapSection(
          analysis.overlaps
        )}
        <section class="route-analysis-section">
          <h3>Prefix hierarchy</h3>
          <div class="route-hierarchy">
            ${analysis.hierarchy
              .map(renderHierarchyNode)
              .join('')}
          </div>
        </section>
        <section class="route-analysis-section">
          <h3>Normalized routes</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Network</th>
                  <th>Next hop</th>
                  <th>Interface</th>
                  <th>Prefix</th>
                  <th>Preference</th>
                  <th>Metric</th>
                  <th>Type</th>
                </tr>
              </thead>
              <tbody>
                ${routes
                  .sort(
                    (a, b) =>
                      a.family -
                        b.family ||
                      a.prefixLength -
                        b.prefixLength ||
                      a.prefix.localeCompare(
                        b.prefix
                      )
                  )
                  .map(
                    route => `
                      <tr>
                        <td>
                          <strong>${escapeHtml(
                            route.prefix
                          )}</strong>
                        </td>
                        <td>
                          ${escapeHtml(
                            route.network
                          )}
                        </td>
                        <td>
                          ${escapeHtml(
                            route.nextHop ||
                              'on-link'
                          )}
                        </td>
                        <td>
                          ${escapeHtml(
                            route.interfaceName ||
                              '-'
                          )}
                        </td>
                        <td>
                          /${route.prefixLength}
                        </td>
                        <td>
                          ${formatNumber(
                            route.preference
                          )}
                        </td>
                        <td>
                          ${formatNumber(
                            route.metric
                          )}
                        </td>
                        <td>
                          ${escapeHtml(
                            route.type ||
                              '-'
                          )}
                        </td>
                      </tr>
                    `
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    `;
  }
  function renderDuplicateSection(
    duplicates
  ) {
    if (!duplicates.length) {
      return `
        <section class="route-analysis-section">
          <h3>Duplicate routes</h3>
          <div class="route-ok">
            No duplicate prefixes detected.
          </div>
        </section>
      `;
    }
    return `
      <section class="route-analysis-section">
        <h3>Duplicate routes</h3>
        ${duplicates
          .map(
            duplicate => `
              <div class="route-warning-block">
                <strong>
                  ⚠ Duplicate prefix:
                  ${escapeHtml(
                    duplicate.prefix
                  )}
                </strong>
                ${duplicate.routes
                  .map(
                    route => `
                      <div class="route-analysis-route">
                        via
                        ${escapeHtml(
                          route.nextHop ||
                            'on-link'
                        )}
                        ${
                          route.interfaceName
                            ? `dev ${escapeHtml(
                                route.interfaceName
                              )}`
                            : ''
                        }
                        ${
                          route.metric !==
                          null
                            ? `metric ${route.metric}`
                            : ''
                        }
                        ${
                          route.preference !==
                          null
                            ? `preference ${route.preference}`
                            : ''
                        }
                      </div>
                    `
                  )
                  .join('')}
              </div>
            `
          )
          .join('')}
      </section>
    `;
  }
  function renderShadowedSection(
    shadowed
  ) {
    if (!shadowed.length) {
      return `
        <section class="route-analysis-section">
          <h3>Shadowed routes</h3>
          <div class="route-ok">
            No completely covered route prefixes detected.
          </div>
        </section>
      `;
    }
    return `
      <section class="route-analysis-section">
        <h3>Shadowed routes</h3>
        ${shadowed
          .map(
            item => `
              <div class="route-warning-block">
                <strong>
                  ⚠ ${escapeHtml(
                    item.route.prefix
                  )} is completely covered
                </strong>
                <div class="small">
                  More-specific routes cover the entire
                  address space of this prefix.
                </div>
                <div class="route-cover-list">
                  ${item.coveringRoutes
                    .map(
                      route =>
                        `<span>${escapeHtml(
                          route.prefix
                        )}</span>`
                    )
                    .join('')}
                </div>
              </div>
            `
          )
          .join('')}
      </section>
    `;
  }
  function renderOverlapSection(
    overlaps
  ) {
    if (!overlaps.length) {
      return `
        <section class="route-analysis-section">
          <h3>Overlapping routes</h3>
          <div class="route-ok">
            No overlapping prefixes detected.
          </div>
        </section>
      `;
    }
    return `
      <section class="route-analysis-section">
        <h3>Overlapping routes</h3>
        <div class="route-overlap-list">
          ${overlaps
            .map(
              overlap => `
                <div class="route-overlap-item">
                  <strong>
                    ${escapeHtml(
                      overlap.broader.prefix
                    )}
                  </strong>
                  <span>contains</span>
                  <strong>
                    ${escapeHtml(
                      overlap.narrower.prefix
                    )}
                  </strong>
                </div>
              `
            )
            .join('')}
        </div>
      </section>
    `;
  }
  function renderHierarchyNode(
    node,
    depth = 0
  ) {
    return `
      <div
        class="route-tree-node"
        style="--route-depth:${depth}"
      >
        <div class="route-tree-entry">
          <span class="route-tree-branch">
            ${depth ? '└─' : ''}
          </span>
          <strong>
            ${escapeHtml(
              node.route.prefix
            )}
          </strong>
          <span class="small">
            via
            ${escapeHtml(
              node.route.nextHop ||
                'on-link'
            )}
          </span>
        </div>
        ${
          node.children.length
            ? `
              <div class="route-tree-children">
                ${node.children
                  .map(child =>
                    renderHierarchyNode(
                      child,
                      depth + 1
                    )
                  )
                  .join('')}
              </div>
            `
            : ''
        }
      </div>
    `;
  }
  function renderTestCommands(destination) {
    const value = formatIp(destination);
    return `
      <div class="route-command-grid">
        <div class="route-command">
          <div class="small">Linux</div>
          <code>ip route get ${escapeHtml(
            value
          )}</code>
          <button
            type="button"
            class="btn"
            data-route-copy="${escapeHtml(
              `ip route get ${value}`
            )}"
          >
            Copy
          </button>
        </div>
        <div class="route-command">
          <div class="small">Windows</div>
          <code>Test-NetConnection ${escapeHtml(
            value
          )}</code>
          <button
            type="button"
            class="btn"
            data-route-copy="${escapeHtml(
              `Test-NetConnection ${value}`
            )}"
          >
            Copy
          </button>
        </div>
        <div class="route-command">
          <div class="small">Cisco</div>
          <code>show ip route ${escapeHtml(
            value
          )}</code>
          <button
            type="button"
            class="btn"
            data-route-copy="${escapeHtml(
              `show ip route ${value}`
            )}"
          >
            Copy
          </button>
        </div>
        <div class="route-command">
          <div class="small">Cisco CEF</div>
          <code>show ip cef ${escapeHtml(
            value
          )}</code>
          <button
            type="button"
            class="btn"
            data-route-copy="${escapeHtml(
              `show ip cef ${value}`
            )}"
          >
            Copy
          </button>
        </div>
      </div>
    `;
  }
  $('#routeDestinationResult').addEventListener(
    'click',
    handleCopyCommand
  );
  async function handleCopyCommand(event) {
    const button =
      event.target.closest(
        '[data-route-copy]'
      );
    if (!button) {
      return;
    }
    const command =
      button.dataset.routeCopy;
    try {
      await navigator.clipboard.writeText(
        command
      );
      const original =
        button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    } catch { }
  }
  function parsePrefix(value) {
    const slash = value.lastIndexOf('/');
    if (slash <= 0) {
      throw new Error(
        `Invalid route prefix: ${value}`
      );
    }
    const addressText =
      value.slice(0, slash);
    const prefixText =
      value.slice(slash + 1);
    const prefixLength =
      Number(prefixText);
    const address =
      parseIpAddress(addressText);
    if (
      !Number.isInteger(prefixLength) ||
      prefixLength < 0 ||
      prefixLength > address.bits
    ) {
      throw new Error(
        `Invalid prefix length in ${value}.`
      );
    }
    const mask =
      prefixMask(
        address.bits,
        prefixLength
      );
    const start =
      address.value & mask;
    const hostBits =
      BigInt(address.bits - prefixLength);
    const size =
      1n << hostBits;
    const end =
      start + size - 1n;
    return {
      family: address.family,
      bits: address.bits,
      prefixLength,
      mask,
      start,
      end,
      size,
      network:
        formatIpValue(
          start,
          address.family
        ),
      prefix:
        `${formatIpValue(
          start,
          address.family
        )}/${prefixLength}`
    };
  }
  function parseIpAddress(value) {
    const text = value.trim();
    if (isIPv4(text)) {
      const numeric =
        ipv4ToBigInt(text);
      return {
        family: 4,
        bits: 32,
        value: numeric,
        mask: (1n << 32n) - 1n
      };
    }
    if (text.includes(':')) {
      const numeric =
        ipv6ToBigInt(text);
      return {
        family: 6,
        bits: 128,
        value: numeric,
        mask: (1n << 128n) - 1n
      };
    }
    throw new Error(
      `Invalid IP address: ${value}`
    );
  }
  function prefixMask(bits, prefixLength) {
    if (prefixLength === 0) {
      return 0n;
    }
    const all =
      (1n << BigInt(bits)) - 1n;
    const hostBits =
      BigInt(bits - prefixLength);
    return (
      all ^
      ((1n << hostBits) - 1n)
    );
  }
  function ipv4ToBigInt(value) {
    const parts = value.split('.');
    if (parts.length !== 4) {
      throw new Error(
        `Invalid IPv4 address: ${value}`
      );
    }
    let result = 0n;
    for (const part of parts) {
      if (!/^\d+$/.test(part)) {
        throw new Error(
          `Invalid IPv4 address: ${value}`
        );
      }
      const number = Number(part);
      if (
        !Number.isInteger(number) ||
        number < 0 ||
        number > 255
      ) {
        throw new Error(
          `Invalid IPv4 address: ${value}`
        );
      }
      result =
        (result << 8n) +
        BigInt(number);
    }
    return result;
  }
  function ipv6ToBigInt(value) {
    let text = value.toLowerCase();
    if (text.includes('.')) {
      const lastColon =
        text.lastIndexOf(':');
      if (lastColon < 0) {
        throw new Error(
          `Invalid IPv6 address: ${value}`
        );
      }
      const ipv4Part =
        text.slice(lastColon + 1);
      const ipv4 =
        ipv4ToBigInt(ipv4Part);
      const high =
        Number(
          (ipv4 >> 16n) & 0xffffn
        );
      const low =
        Number(
          ipv4 & 0xffffn
        );
      text =
        `${text.slice(
          0,
          lastColon
        )}:${high.toString(16)}:${low.toString(16)}`;
    }
    const doubleColon =
      text.indexOf('::');
    let groups;
    if (doubleColon >= 0) {
      if (
        text.indexOf(
          '::',
          doubleColon + 1
        ) >= 0
      ) {
        throw new Error(
          `Invalid IPv6 address: ${value}`
        );
      }
      const left =
        text
          .slice(0, doubleColon)
          .split(':')
          .filter(Boolean);
      const right =
        text
          .slice(doubleColon + 2)
          .split(':')
          .filter(Boolean);
      const missing =
        8 - left.length - right.length;
      if (missing < 1) {
        throw new Error(
          `Invalid IPv6 address: ${value}`
        );
      }
      groups = [
        ...left,
        ...Array(missing).fill('0'),
        ...right
      ];
    } else {
      groups =
        text.split(':');
    }
    if (groups.length !== 8) {
      throw new Error(
        `Invalid IPv6 address: ${value}`
      );
    }
    let result = 0n;
    for (const group of groups) {
      if (
        !/^[0-9a-f]{1,4}$/i.test(group)
      ) {
        throw new Error(
          `Invalid IPv6 address: ${value}`
        );
      }
      result =
        (result << 16n) +
        BigInt(
          parseInt(group, 16)
        );
    }
    return result;
  }
  function formatIp(address) {
    return formatIpValue(
      address.value,
      address.family
    );
  }
  function formatIpValue(
    value,
    family
  ) {
    if (family === 4) {
      const parts = [];
      for (let i = 3; i >= 0; i--) {
        parts.push(
          Number(
            (value >>
              BigInt(i * 8)) &
              0xffn
          )
        );
      }
      return parts.join('.');
    }
    const groups = [];
    for (let i = 7; i >= 0; i--) {
      groups.push(
        Number(
          (value >>
            BigInt(i * 16)) &
            0xffffn
        )
          .toString(16)
      );
    }
    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;
    let currentLength = 0;
    for (
      let i = 0;
      i <= groups.length;
      i++
    ) {
      const zero =
        i < groups.length &&
        groups[i] === '0';
      if (zero) {
        if (currentStart < 0) {
          currentStart = i;
          currentLength = 1;
        } else {
          currentLength++;
        }
      } else {
        if (
          currentLength > bestLength &&
          currentLength >= 2
        ) {
          bestStart = currentStart;
          bestLength = currentLength;
        }
        currentStart = -1;
        currentLength = 0;
      }
    }
    if (bestStart >= 0) {
      groups.splice(
        bestStart,
        bestLength,
        ''
      );
      if (bestStart === 0) {
        groups.unshift('');
      }
      if (
        bestStart + bestLength ===
        8
      ) {
        groups.push('');
      }
    }
    return groups.join(':');
  }
  function isCidr(value) {
    if (!value.includes('/')) {
      return false;
    }
    try {
      parsePrefix(value);
      return true;
    } catch {
      return false;
    }
  }
  function isIPv4(value) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(
      value
    );
  }
  function isIpAddressSafe(value) {
    try {
      parseIpAddress(value);
      return true;
    } catch {
      return false;
    }
  }
  function isNumber(value) {
    return /^\d+$/.test(value);
  }
  function isInterfaceToken(value) {
    return (
      /^(eth|ens|eno|enp|bond|br|lo|tun|tap|wg|ge-|xe-|et-|gi|te|fa|po|vlan|wan|lan)/i.test(
        value
      ) ||
      /^[A-Za-z]+\d+(?:[/.:-]\d+)*$/.test(
        value
      )
    );
  }
  function ipv4MaskToPrefix(mask) {
    if (!isIPv4(mask)) {
      throw new Error(
        `Invalid IPv4 netmask: ${mask}`
      );
    }
    const numeric =
      ipv4ToBigInt(mask);
    let seenZero = false;
    let prefixLength = 0;
    for (let bit = 31; bit >= 0; bit--) {
      const value =
        (numeric >>
          BigInt(bit)) &
        1n;
      if (value === 1n) {
        if (seenZero) {
          throw new Error(
            `Invalid IPv4 netmask: ${mask}`
          );
        }
        prefixLength++;
      } else {
        seenZero = true;
      }
    }
    return prefixLength;
  }
  function valueAfter(tokens, key) {
    const index =
      tokens.findIndex(
        token =>
          token.toLowerCase() ===
          key.toLowerCase()
      );
    return index >= 0
      ? tokens[index + 1] || ''
      : '';
  }
  function numberAfter(tokens, key) {
    const value =
      valueAfter(tokens, key);
    if (!value) {
      return null;
    }
    const number = Number(value);
    return Number.isFinite(number)
      ? number
      : null;
  }
  function ciscoCodeToType(code) {
    const value = code
      .replace('*', '')
      .charAt(0)
      .toUpperCase();
    const types = {
      C: 'connected',
      L: 'local',
      S: 'static',
      O: 'ospf',
      D: 'eigrp',
      B: 'bgp',
      R: 'rip',
      I: 'isis'
    };
    return types[value] || code;
  }
  function formatNumber(value) {
    return value === null ||
      value === undefined ||
      Number.isNaN(value)
      ? '-'
      : String(value);
  }
  function formatIpAddressFamily(
    family
  ) {
    return family === 6
      ? 'IPv6'
      : 'IPv4';
  }
  function formatLabel(format) {
    const labels = {
      auto: 'Auto',
      normalized: 'Normalized table',
      linux: 'Linux ip route',
      windows: 'Windows route print',
      cisco: 'Cisco show ip route',
      juniper: 'Juniper show route'
    };
    return (
      labels[format] ||
      format
    );
  }
  function createRouteId() {
    return `route-${Math.random()
      .toString(36)
      .slice(2, 10)}`;
  }
  function serializeAnalysis(value) {
    return JSON.parse(
      JSON.stringify(
        value,
        (_, current) =>
          typeof current === 'bigint'
            ? current.toString()
            : current
      )
    );
  }
  function buildExportText(analysis) {
    const lines = [
      'Route Calculator & Simulator',
      '================================',
      ''
    ];
    if (
      analysis.kind ===
      'destination'
    ) {
      lines.push(
        `Destination: ${analysis.destination}`
      );
      lines.push(
        `Profile: ${analysis.profile}`
      );
      lines.push(
        `Input format: ${analysis.detectedFormat}`,
        ''
      );
      lines.push('Matched routes:');
      for (const route of analysis.decision.matched) {
        lines.push(
          `  ${route.prefix} via ${
            route.nextHop || 'on-link'
          } dev ${
            route.interfaceName || '-'
          } metric ${
            formatNumber(route.metric)
          }`
        );
      }
      lines.push('');
      if (analysis.decision.selected) {
        lines.push(
          `Selected: ${analysis.decision.selected.prefix}`
        );
        lines.push(
          `Next hop: ${
            analysis.decision.selected.nextHop ||
            'on-link'
          }`
        );
        lines.push(
          `Interface: ${
            analysis.decision.selected.interfaceName ||
            '-'
          }`
        );
      } else {
        lines.push(
          'Selected: No matching route'
        );
      }
    }
    if (
      analysis.kind ===
      'simulator'
    ) {
      lines.push(
        `Profile: ${analysis.profile}`,
        `Input format: ${analysis.detectedFormat}`,
        ''
      );
      for (const result of analysis.results) {
        if (result.error) {
          lines.push(
            `${result.input}: ERROR ${result.error}`
          );
          continue;
        }
        const selected =
          result.decision.selected;
        lines.push(
          `${result.input}: ${
            selected
              ? selected.prefix
              : 'NO MATCH'
          }`
        );
      }
    }
    if (
      analysis.kind ===
      'table-analysis'
    ) {
      lines.push(
        `Input format: ${analysis.detectedFormat}`,
        `Routes: ${analysis.routes.length}`,
        `Duplicates: ${analysis.analysis.duplicates.length}`,
        `Overlaps: ${analysis.analysis.overlaps.length}`,
        `Shadowed: ${analysis.analysis.shadowed.length}`,
        ''
      );
      lines.push(
        'Routes:'
      );
      for (const route of analysis.routes) {
        lines.push(
          `${route.prefix} via ${
            route.nextHop || 'on-link'
          } dev ${
            route.interfaceName || '-'
          }`
        );
      }
      lines.push('');
      lines.push(
        'Shadowed routes:'
      );
      for (
        const item of
        analysis.analysis.shadowed
      ) {
        lines.push(
          `  ${item.route.prefix} covered by ${item.coveringRoutes
            .map(route => route.prefix)
            .join(', ')}`
        );
      }
    }
    return lines.join('\n');
  }
  function showError(
    selector,
    message
  ) {
    $(selector).innerHTML = `
      <div class="tool-status tool-status-error">
        ${escapeHtml(message)}
      </div>
    `;
  }
  function createExample() {
    return {
      destination:
        '10.20.30.45',
      table: `
0.0.0.0/0          192.168.1.1     eth0    100   static
10.0.0.0/8         10.0.0.1        eth1    10    static
10.20.0.0/16       10.20.0.1       eth2    20    static
10.20.30.0/24      10.20.30.1      eth3    50    static
10.20.30.32/27     10.20.30.33     eth4    5     static
`.trim(),
      destinations: [
        '10.20.30.45',
        '10.20.30.100',
        '10.20.50.12',
        '10.50.1.8',
        '8.8.8.8',
        '2001:db8:1234:5678::42'
      ],
      analysisTable: `
0.0.0.0/0          192.168.1.1     eth0    100   static
10.0.0.0/8         10.0.0.1        eth1    10    static
10.20.0.0/16       10.20.0.1       eth2    20    static
10.20.30.0/24      10.20.30.1      eth3    50    static
10.20.30.0/24      10.20.30.254    eth5    60    static
10.20.30.0/25      10.20.30.1      eth3    10    static
10.20.30.128/25    10.20.30.129    eth6    10    static
192.168.0.0/16     192.168.1.1     eth0    100   static
`.trim()
    };
  }
}