import { $, escapeHtml, downloadText } from '../utils.js';

export const metadata = {
  id: 'dism',
  title: 'DISM Analyzer',
  description: 'Parse and interpret Windows DISM output locally',
  path: '/#dism'
};

export function renderDism(app) {
  app.innerHTML = `
    <div class="tool-window" id="dismWindow">
      <div class="tool-window-header" id="dismDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>DISM Analyzer</strong>
      </div>

      <section class="card">
        <h2>DISM output analyzer</h2>

        <p class="small">
          Paste output from <code>DISM</code>, <code>DISM /Online</code>,
          <code>/Get-*</code>, <code>/ScanHealth</code>,
          <code>/CheckHealth</code>, <code>/RestoreHealth</code>,
          package/feature/capability queries or similar commands.
          Everything is parsed locally in your browser.
        </p>

        <textarea
          id="dismInput"
          spellcheck="false"
          placeholder="Paste DISM output here...

Example:

Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26100.1742

No component store corruption detected.
The operation completed successfully."
        ></textarea>

        <div class="row" style="margin-top:10px">
          <button class="btn primary" id="dismAnalyze">Analyze</button>
          <button class="btn" id="dismClear">Clear</button>
          <button class="btn" id="dismExample">Load example</button>
        </div>

        <div id="dismInputInfo" class="small" style="margin-top:10px"></div>
      </section>

      <section class="card" id="dismResult" hidden></section>
    </div>
  `;

  $('#dismAnalyze').onclick = analyze;
  $('#dismClear').onclick = clear;
  $('#dismExample').onclick = loadExample;

  $('#dismInput').addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      analyze();
    }
  });

  enableDraggingIfAvailable();

  function analyze() {
    const raw = $('#dismInput').value;
    const result = $('#dismResult');

    if (!raw.trim()) {
      result.hidden = false;
      result.innerHTML = `
        <div class="status warning">
          Paste DISM output first.
        </div>
      `;
      return;
    }

    try {
      const analysis = analyzeDism(raw);

      result.hidden = false;
      result.innerHTML = renderResult(analysis);

      bindExports(analysis);
    } catch (error) {
      result.hidden = false;
      result.innerHTML = `
        <div class="status danger">
          ${escapeHtml(error.message || 'DISM output could not be parsed.')}
        </div>
      `;
    }
  }

  function clear() {
    $('#dismInput').value = '';
    $('#dismInputInfo').textContent = '';
    $('#dismResult').hidden = true;
    $('#dismResult').innerHTML = '';
  }

  function loadExample() {
    $('#dismInput').value = EXAMPLE_DISM_OUTPUT;
    $('#dismInputInfo').textContent =
      'Example DISM output loaded locally.';

    analyze();
  }

  function enableDraggingIfAvailable() {
    try {
      const utilsModule = arguments;
      void utilsModule;
      enableToolDragging(
        $('#dismWindow'),
        $('#dismDragHandle')
      );
    } catch {
    }
  }
}

function analyzeDism(raw) {
  const text = normalizeText(raw);
  const lines = text.split('\n');
  const sections = detectSections(lines);
  const version = parseVersions(lines);
  const operation = detectOperation(text);
  const health = parseHealth(text);
  const result = parseOperationResult(text);
  const image = parseImageInformation(lines);
  const packages = parsePackages(lines);
  const features = parseFeatures(lines);
  const capabilities = parseCapabilities(lines);
  const drivers = parseDrivers(lines);
  const cleanup = parseCleanup(lines, text);
  const componentStore = parseComponentStore(lines, text);
  const errors = parseErrors(lines);
  const warnings = parseWarnings(lines);
  const reboot = detectRebootRequirement(text);
  const progress = parseProgress(text);
  const source = parseRepairSource(lines, text);
  const commands = detectCommands(lines);
  const observations = buildObservations({
    health,
    result,
    packages,
    features,
    capabilities,
    drivers,
    cleanup,
    componentStore,
    errors,
    warnings,
    reboot,
    source,
    operation
  });
  const summary = buildSummary({
    health,
    result,
    errors,
    warnings,
    reboot,
    packages,
    features,
    drivers,
    observations
  });
  return {
    raw,
    lines,
    summary,
    operation,
    version,
    health,
    result,
    image,
    packages,
    features,
    capabilities,
    drivers,
    cleanup,
    componentStore,
    errors,
    warnings,
    reboot,
    progress,
    source,
    commands,
    sections,
    observations,
    counts: {
      lines: lines.length,
      packages: packages.length,
      features: features.length,
      capabilities: capabilities.length,
      drivers: drivers.length,
      errors: errors.length,
      warnings: warnings.length
    }
  };
}
function normalizeText(raw) {
  return String(raw || '')
    .replace(/^\uFEFF/, '')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\u00a0/g, ' ');
}
function parseVersions(lines) {
  const result = {
    dismVersion: '',
    imageVersion: '',
    osVersion: ''
  };
  for (const line of lines) {
    let match = line.match(
      /^\s*(?:DISM\s+tool\s+version|Version)\s*:\s*(.+)$/i
    );
    if (match && !result.dismVersion) {
      result.dismVersion = match[1].trim();
      continue;
    }
    match = line.match(/^\s*Image Version\s*:\s*(.+)$/i);
    if (match && !result.imageVersion) {
      result.imageVersion = match[1].trim();
      continue;
    }
    match = line.match(/^\s*(?:OS|Operating System)\s+Version\s*:\s*(.+)$/i);
    if (match && !result.osVersion) {
      result.osVersion = match[1].trim();
    }
  }
  return result;
}

function detectOperation(text) {
  const lower = text.toLowerCase();
  const checks = [
    [/scanhealth|scanhealth/i, 'ScanHealth'],
    [/checkhealth/i, 'CheckHealth'],
    [/restorehealth/i, 'RestoreHealth'],
    [/startcomponentcleanup/i, 'StartComponentCleanup'],
    [/resetbase/i, 'ResetBase'],
    [/analyzecomponentstore/i, 'AnalyzeComponentStore'],
    [/get-packages/i, 'Get-Packages'],
    [/get-features/i, 'Get-Features'],
    [/get-capabilities/i, 'Get-Capabilities'],
    [/get-drivers/i, 'Get-Drivers'],
    [/get-wiminfo/i, 'Get-WimInfo'],
    [/get-imageinfo/i, 'Get-ImageInfo'],
    [/add-package/i, 'Add-Package'],
    [/remove-package/i, 'Remove-Package'],
    [/enable-feature/i, 'Enable-Feature'],
    [/disable-feature/i, 'Disable-Feature'],
    [/add-capability/i, 'Add-Capability'],
    [/remove-capability/i, 'Remove-Capability'],
    [/cleanup-image/i, 'Cleanup-Image']
  ];

  const found = [];
  for (const [regex, name] of checks) {
    if (regex.test(lower)) found.push(name);
  }

  return found.length ? found : ['Unknown / not explicitly identifiable'];
}

function parseImageInformation(lines) {
  const result = {
    imageVersion: '',
    architecture: '',
    edition: '',
    name: '',
    description: '',
    language: '',
    build: ''
  };
  for (const line of lines) {
    const trimmed = line.trim();
    let match = trimmed.match(/^Image Version\s*:\s*(.+)$/i);
    if (match) result.imageVersion = match[1].trim();
    match = trimmed.match(/^(?:Architecture|Architektur)\s*:\s*(.+)$/i);
    if (match) result.architecture = match[1].trim();
    match = trimmed.match(/^(?:Edition|Edition\s*ID)\s*:\s*(.+)$/i);
    if (match) result.edition = match[1].trim();
    match = trimmed.match(/^Name\s*:\s*(.+)$/i);
    if (match) result.name = match[1].trim();
    match = trimmed.match(/^Description\s*:\s*(.+)$/i);
    if (match) result.description = match[1].trim();
    match = trimmed.match(/^(?:Language|Sprache)\s*:\s*(.+)$/i);
    if (match) result.language = match[1].trim();
  }

  if (result.imageVersion) {
    result.build = extractBuild(result.imageVersion);
  }
  return result;
}

function extractBuild(version) {
  const match = String(version).match(
    /^\d+\.\d+\.(\d+)(?:\.(\d+))?/
  );
  if (!match) return '';
  return match[2]
    ? `${match[1]}.${match[2]}`
    : match[1];
}

function parseHealth(text) {
  const lower = text.toLowerCase();
  const health = {
    state: 'unknown',
    label: 'Unknown',
    evidence: []
  };
  const goodPatterns = [
    'no component store corruption detected',
    'component store corruption was not detected',
    'keine beschädigung des komponentspeichers',
    'keine beschädigung des komponentenspeichers',
    'component store is repairable: no',
    'the component store is repairable: no',
    'image is healthy',
    'image is healthy.',
    'das image ist fehlerfrei'
  ];
  const repairablePatterns = [
    'component store corruption is repairable',
    'component store corruption was detected',
    'the component store is repairable: yes',
    'beschädigung des komponentspeichers wurde erkannt',
    'beschädigung des komponentenspeichers wurde erkannt',
    'das image kann repariert werden'
  ];
  const unrecoverablePatterns = [
    'component store corruption cannot be repaired',
    'the component store cannot be repaired',
    'image is not repairable',
    'das image kann nicht repariert werden'
  ];
  if (containsAny(lower, unrecoverablePatterns)) {
    health.state = 'bad';
    health.label = 'Component store may be unrecoverable';
  } else if (containsAny(lower, repairablePatterns)) {
    health.state = 'warn';
    health.label = 'Component store corruption detected / repairable';
  } else if (containsAny(lower, goodPatterns)) {
    health.state = 'good';
    health.label = 'No component-store corruption detected';
  }
  for (const pattern of [
    ...goodPatterns,
    ...repairablePatterns,
    ...unrecoverablePatterns
  ]) {
    if (lower.includes(pattern)) {
      health.evidence.push(pattern);
    }
  }

  return health;
}
function parseOperationResult(text) {
  const lower = text.toLowerCase();
  if (
    /operation completed successfully|der vorgang wurde erfolgreich abgeschlossen|vorgang erfolgreich abgeschlossen/i.test(
      text
    )
  ) {
    return {
      state: 'good',
      label: 'Operation completed successfully'
    };
  }
  if (
    /operation completed with errors|operation failed|error:|fehler:/i.test(
      text
    )
  ) {
    return {
      state: 'bad',
      label: 'Operation reported errors'
    };
  }
  if (
    /operation is pending|pending|ausstehend|neustart.*erforderlich|restart.*required/i.test(
      lower
    )
  ) {
    return {
      state: 'warn',
      label: 'Operation may require completion after restart'
    };
  }
  return {
    state: 'unknown',
    label: 'Operation result not explicitly reported'
  };
}
function detectRebootRequirement(text) {
  const patterns = [
    /restart.*required/i,
    /reboot.*required/i,
    /you must restart/i,
    /a restart is required/i,
    /neustart.*erforderlich/i,
    /neustart.*notwendig/i,
    /system.*neu gestartet/i,
    /ausstehend/i
  ];
  const found = patterns.filter(regex => regex.test(text));
  return {
    required: found.length > 0,
    evidence: found.map(String)
  };
}

function parsePackages(lines) {
  const packages = [];
  let current = null;
  for (const line of lines) {
    const trimmed = line.trim();
    let match = trimmed.match(
      /^Package Identity\s*:\s*(.+)$/i
    );
    if (!match) {
      match = trimmed.match(
        /^Paketidentität\s*:\s*(.+)$/i
      );
    }
    if (match) {
      if (current) packages.push(current);
      current = {
        identity: match[1].trim(),
        state: '',
        releaseType: '',
        installTime: '',
        applicable: '',
        raw: []
      };
      continue;
    }
    if (!current) continue;
    current.raw.push(trimmed);
    const fields = [
      ['state', /^(?:State|Status)\s*:\s*(.+)$/i],
      ['releaseType', /^(?:Release Type|Freigabetyp)\s*:\s*(.+)$/i],
      ['installTime', /^(?:Install Time|Installationszeit)\s*:\s*(.+)$/i],
      ['applicable', /^(?:Applicable|Anwendbar)\s*:\s*(.+)$/i]
    ];
    for (const [key, regex] of fields) {
      const m = trimmed.match(regex);
      if (m) current[key] = m[1].trim();
    }
  }
  if (current) packages.push(current);
  return packages;
}
function parseFeatures(lines) {
  const features = [];
  for (const line of lines) {
    const trimmed = line.trim();
    let match = trimmed.match(
      /^Feature Name\s*:\s*(.+)$/i
    );
    if (!match) {
      match = trimmed.match(
        /^Funktionsname\s*:\s*(.+)$/i
      );
    }
    if (!match) continue;
    const feature = {
      name: match[1].trim(),
      state: ''
    };
    const index = lines.indexOf(line);
    for (let i = index + 1; i < Math.min(lines.length, index + 5); i++) {
      const stateMatch = lines[i].trim().match(
        /^(?:State|Status)\s*:\s*(.+)$/i
      );
      if (stateMatch) {
        feature.state = stateMatch[1].trim();
        break;
      }
    }
    features.push(feature);
  }
  return dedupeBy(features, x => `${x.name}|${x.state}`);
}
function parseCapabilities(lines) {
  const capabilities = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    let match = trimmed.match(
      /^Capability Identity\s*:\s*(.+)$/i
    );
    if (!match) {
      match = trimmed.match(
        /^Kapazitätsidentität\s*:\s*(.+)$/i
      );
    }
    if (!match) continue;
    const capability = {
      identity: match[1].trim(),
      state: '',
      downloadSize: '',
      installSize: ''
    };
    for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
      const next = lines[j].trim();
      let state = next.match(
        /^(?:State|Status)\s*:\s*(.+)$/i
      );
      if (state) capability.state = state[1].trim();
      let download = next.match(
        /^(?:Download Size|Downloadgröße)\s*:\s*(.+)$/i
      );
      if (download) capability.downloadSize = download[1].trim();
      let install = next.match(
        /^(?:Install Size|Installationsgröße)\s*:\s*(.+)$/i
      );
      if (install) capability.installSize = install[1].trim();
    }
    capabilities.push(capability);
  }
  return capabilities;
}

function parseDrivers(lines) {
  const drivers = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (
      !/Published Name|Veröffentlichter Name/i.test(line)
    ) {
      continue;
    }
    const driver = {
      publishedName: '',
      originalName: '',
      providerName: '',
      className: '',
      classGuid: '',
      version: '',
      date: '',
      signerName: ''
    };
    const firstMatch = line.match(
      /^(?:Published Name|Veröffentlichter Name)\s*:\s*(.+)$/i
    );
    if (firstMatch) {
      driver.publishedName = firstMatch[1].trim();
    }
    for (let j = i + 1; j < Math.min(lines.length, i + 15); j++) {
      const current = lines[j].trim();
      assignIfMatch(
        driver,
        'originalName',
        current,
        /^(?:Original Name|Originalname)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'providerName',
        current,
        /^(?:Provider Name|Anbietername)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'className',
        current,
        /^(?:Class Name|Klassenname)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'classGuid',
        current,
        /^(?:Class GUID|Klassen-GUID)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'version',
        current,
        /^(?:Driver Version|Treiberversion)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'date',
        current,
        /^(?:Date|Datum)\s*:\s*(.+)$/i
      );
      assignIfMatch(
        driver,
        'signerName',
        current,
        /^(?:Signer Name|Signaturgebername)\s*:\s*(.+)$/i
      );
    }
    drivers.push(driver);
  }
  return dedupeBy(drivers, x => x.publishedName || JSON.stringify(x));
}

function parseCleanup(lines, text) {
  const lower = text.toLowerCase();
  const result = {
    detected: false,
    reclaimable: '',
    recommended: '',
    resetBase: false
  };
  result.detected =
    /startcomponentcleanup|analyzecomponentstore|cleanup-image/i.test(
      text
    );
  const reclaimablePatterns = [
    /reclaimable packages\s*:\s*(.+)/i,
    /wiederherstellbare pakete\s*:\s*(.+)/i,
    /reclaimable packages\s*:\s*(.+)/i
  ];
  for (const regex of reclaimablePatterns) {
    const match = text.match(regex);
    if (match) {
      result.reclaimable = match[1].trim();
      break;
    }
  }
  if (
    /recommended cleanup\s*:\s*yes/i.test(text) ||
    /bereinigung.*empfohlen/i.test(lower)
  ) {
    result.recommended = 'Yes';
  } else if (
    /recommended cleanup\s*:\s*no/i.test(text)
  ) {
    result.recommended = 'No';
  }
  result.resetBase =
    /resetbase/i.test(text);
  return result;
}
function parseComponentStore(lines, text) {
  const result = {
    detected: false,
    corruption: '',
    repairable: '',
    size: '',
    actualSize: '',
    sharedWithWindows: '',
    backupsAndDisabledFeatures: '',
    cacheAndTemporaryData: ''
  };
  result.detected =
    /component store|komponentenspeicher|komponentenspeicher/i.test(
      text
    );
  for (const line of lines) {
    const trimmed = line.trim();
    assignIfMatch(
      result,
      'size',
      trimmed,
      /^(?:Component Store Size|Größe des Komponentenspeichers)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'actualSize',
      trimmed,
      /^(?:Actual Size|Tatsächliche Größe)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'sharedWithWindows',
      trimmed,
      /^(?:Shared with Windows|Gemeinsam mit Windows)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'backupsAndDisabledFeatures',
      trimmed,
      /^(?:Backups and Disabled Features|Sicherungen und deaktivierte Features)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'cacheAndTemporaryData',
      trimmed,
      /^(?:Cache and Temporary Data|Cache und temporäre Daten)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'corruption',
      trimmed,
      /^(?:Corruption|Beschädigung)\s*:\s*(.+)$/i
    );
    assignIfMatch(
      result,
      'repairable',
      trimmed,
      /^(?:Repairable|Reparierbar)\s*:\s*(.+)$/i
    );
  }
  return result;
}

function parseErrors(lines) {
  const errors = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (
      /^error\b/i.test(line) ||
      /^fehler\b/i.test(line) ||
      /\bError:\s*/i.test(line) ||
      /\bFehler:\s*/i.test(line)
    ) {
      errors.push({
        line: i + 1,
        text: line,
        code: extractErrorCode(line)
      });
    }
    if (
      /error 0x[0-9a-f]+/i.test(line) ||
      /fehler 0x[0-9a-f]+/i.test(line)
    ) {
      if (!errors.some(e => e.line === i + 1)) {
        errors.push({
          line: i + 1,
          text: line,
          code: extractErrorCode(line)
        });
      }
    }
  }

  return errors;
}
function extractErrorCode(text) {
  const match = text.match(
    /\b(0x[0-9a-f]{4,16})\b/i
  );
  return match ? match[1].toUpperCase() : '';
}

function parseWarnings(lines) {
  const warnings = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (
      /^warning\b/i.test(line) ||
      /^warnung\b/i.test(line) ||
      /\bwarning:/i.test(line) ||
      /\bwarnung:/i.test(line)
    ) {
      warnings.push({
        line: i + 1,
        text: line
      });
    }
  }
  return warnings;
}

function parseProgress(text) {
  const percentages = [];
  for (const match of text.matchAll(
    /(\d{1,3}(?:\.\d+)?)\s*%/g
  )) {
    const value = Number(match[1]);
    if (value >= 0 && value <= 100) {
      percentages.push(value);
    }
  }
  return {
    detected: percentages.length > 0,
    values: percentages,
    last: percentages.length
      ? percentages[percentages.length - 1]
      : null
  };
}
function parseRepairSource(lines, text) {
  const result = {
    detected: false,
    source: '',
    explicit: false
  };
  const sourcePatterns = [
    /source\s*:\s*(.+)$/i,
    /quelle\s*:\s*(.+)$/i,
    /source path\s*:\s*(.+)$/i,
    /quellpfad\s*:\s*(.+)$/i
  ];

  for (const regex of sourcePatterns) {
    const match = text.match(regex);

    if (match) {
      result.detected = true;
      result.explicit = true;
      result.source = match[1].trim();
      break;
    }
  }
  if (
    /\/source[:\s]/i.test(text) ||
    /-source[:\s]/i.test(text)
  ) {
    result.detected = true;
  }

  return result;
}
function detectCommands(lines) {
  const commands = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (
      /^(?:DISM(?:\.exe)?\s+)?\/[a-z]/i.test(trimmed) ||
      /^DISM(?:\.exe)?\s+/i.test(trimmed)
    ) {
      commands.push(trimmed);
    }
  }

  return dedupeBy(commands, x => x);
}

function detectSections(lines) {
  const sections = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed) continue;
    if (
      isHeading(trimmed)
    ) {
      current = {
        title: trimmed,
        startLine: i + 1,
        lines: []
      };
      sections.push(current);
      continue;
    }
    if (current) {
      current.lines.push({
        number: i + 1,
        text: trimmed
      });
    }
  }
  return sections;
}

function isHeading(line) {
  if (line.length > 100) return false;
  if (/^[=-]{3,}$/.test(line)) return false;
  return (
    /^(deployment|bereitstellungs|image|image servicing|package|paket|feature|funktion|capability|treiber|driver|component store|komponentenspeicher|error|fehler|warning|warnung)/i.test(
      line
    )
  );
}

function buildObservations(data) {
  const observations = [];

  if (data.health.state === 'good') {
    observations.push({
      level: 'good',
      title: 'Component store health looks good',
      text: 'The supplied output contains a positive health indication.'
    });
  }

  if (data.health.state === 'warn') {
    observations.push({
      level: 'warn',
      title: 'Component store requires attention',
      text: 'DISM output indicates corruption or another condition for which repair may be possible.'
    });
  }

  if (data.health.state === 'bad') {
    observations.push({
      level: 'bad',
      title: 'Component store may not be repairable',
      text: 'The supplied output contains an indication that the image/component store cannot be repaired normally.'
    });
  }

  if (data.result.state === 'good') {
    observations.push({
      level: 'good',
      title: 'DISM operation completed',
      text: data.result.label
    });
  }

  if (data.result.state === 'bad') {
    observations.push({
      level: 'bad',
      title: 'DISM reported an error',
      text: 'Inspect the error codes below before taking further action.'
    });
  }

  if (data.reboot.required) {
    observations.push({
      level: 'warn',
      title: 'Restart may be required',
      text: 'The output contains an indication of a pending operation or required restart.'
    });
  }

  for (const error of data.errors) {
    observations.push({
      level: 'bad',
      title: error.code
        ? `DISM error ${error.code}`
        : 'DISM error',
      text: error.text
    });
  }

  for (const warning of data.warnings) {
    observations.push({
      level: 'warn',
      title: 'DISM warning',
      text: warning.text
    });
  }

  for (const pkg of data.packages) {
    const state = classifyPackageState(pkg.state);

    if (state === 'pending') {
      observations.push({
        level: 'warn',
        title: 'Package pending',
        text: pkg.identity
      });
    }

    if (state === 'superseded') {
      observations.push({
        level: 'warn',
        title: 'Superseded package',
        text: pkg.identity
      });
    }
    if (state === 'installed') {
    }
  }

  for (const driver of data.drivers) {
    if (
      driver.signerName &&
      /unsigned|nicht signiert/i.test(driver.signerName)
    ) {
      observations.push({
        level: 'warn',
        title: 'Unsigned driver reported',
        text: `${driver.publishedName || driver.originalName || 'Unknown driver'}`
      });
    }
  }

  if (data.cleanup.recommended === 'Yes') {
    observations.push({
      level: 'warn',
      title: 'Component cleanup appears recommended',
      text: 'The supplied output indicates that cleanup may be useful.'
    });
  }

  if (data.source.detected) {
    observations.push({
      level: 'neutral',
      title: 'Repair source detected',
      text: data.source.source || 'A /Source or equivalent repair source was referenced.'
    });
  }

  return observations;
}

function buildSummary(data) {
  let state = 'neutral';
  let title = 'DISM output parsed';
  let text =
    'The output was parsed locally. Review the sections below for image, health, package and error information.';

  if (data.errors.length > 0 || data.health.state === 'bad') {
    state = 'bad';
    title = 'DISM reported a problem';
    text =
      'The supplied output contains errors or indications that the image/component store may not be repairable.';
  } else if (
    data.health.state === 'warn' ||
    data.result.state === 'bad' ||
    data.warnings.length > 0 ||
    data.reboot.required
  ) {
    state = 'warn';
    title = 'DISM output needs attention';
    text =
      'The output contains warnings, pending operations, or health information that should be reviewed.';
  } else if (
    data.health.state === 'good' &&
    data.result.state === 'good'
  ) {
    state = 'good';
    title = 'DISM operation looks healthy';
    text =
      'The supplied output contains positive component-store health information and a successful operation result.';
  } else if (data.result.state === 'good') {
    state = 'good';
    title = 'DISM operation completed successfully';
    text =
      'DISM reported successful completion. No explicit component-store problem was detected in the supplied output.';
  }

  return {
    state,
    title,
    text
  };
}

function renderResult(a) {
  const summary = `
    <div class="status ${statusClass(a.summary.state)}">
      <strong>
        <span aria-hidden="true" style="font-size:1.15em;margin-right:6px">
          ${statusIcon(a.summary.state)}
        </span>
        ${escapeHtml(a.summary.title)}
      </strong>
      <br>
      <span>${escapeHtml(a.summary.text)}</span>
    </div>
  `;
  const overview = `
    <h3>Overview</h3>
    <div class="grid">
      ${stat('DISM version', a.version.dismVersion || 'Not found')}
      ${stat('Image version', a.version.imageVersion || 'Not found')}
      ${stat('Image build', a.version.build || 'Not found')}
      ${stat('Architecture', a.image.architecture || 'Not found')}
      ${stat('Edition', a.image.edition || 'Not found')}
      ${stat('Operation', a.operation.join(', '))}
    </div> `;
  const health = `
    <h3>Health</h3>
    <div class="grid">
      ${healthStat('Component store', a.health.state, a.health.label)}
      ${healthStat('Operation result', a.result.state, a.result.label)}
      ${healthStat(
        'Restart',
        a.reboot.required ? 'warn' : 'good',
        a.reboot.required ? 'Restart may be required' : 'No restart requirement detected'
      )}
    </div>`;
  const observations = `
    <h3>Interpretation</h3>
    ${
      a.observations.length
        ? a.observations.map(renderObservation).join('')
        : `<div class="status">No additional heuristic observations were generated.</div>`
    }
  `;
  const image = `
    <h3>Image information</h3>
    <div class="grid">
      ${stat('Name', a.image.name || 'Not found')}
      ${stat('Description', a.image.description || 'Not found')}
      ${stat('Edition', a.image.edition || 'Not found')}
      ${stat('Architecture', a.image.architecture || 'Not found')}
      ${stat('Language', a.image.language || 'Not found')}
      ${stat('Build', a.image.build || 'Not found')}
    </div>
  `;
  const packages = renderPackages(a.packages);
  const features = renderFeatures(a.features);
  const capabilities = renderCapabilities(a.capabilities);
  const drivers = renderDrivers(a.drivers);
  const componentStore = renderComponentStore(a.componentStore);
  const cleanup = renderCleanup(a.cleanup);
  const errors = renderErrors(a.errors);
  const warnings = renderWarnings(a.warnings);
  const source = renderSource(a.source);
  const commands = renderCommands(a.commands);
  const exports = `
    <div class="result-actions">
      <button class="btn" id="dismExportJson">Export analysis JSON</button>
      <button class="btn" id="dismExportText">Export summary TXT</button>
    </div>
  `;
  const raw = `
    <h3>Raw output</h3>
    <details>
      <summary>Show original DISM output</summary>
      <pre class="mono" style="white-space:pre-wrap;max-height:500px;overflow:auto">${escapeHtml(a.raw)}</pre>
    </details>
  `;

  return `
    ${summary}
    ${exports}
    ${overview}
    ${health}
    ${observations}
    ${image}
    ${componentStore}
    ${cleanup}
    ${source}
    ${packages}
    ${features}
    ${capabilities}
    ${drivers}
    ${errors}
    ${warnings}
    ${commands}
    ${raw}

    <details style="margin-top:14px">
      <summary>Parser notes</summary>
      <p class="small">
        This analyzer interprets text produced by DISM. It does not execute DISM, inspect the Windows installation, verify package signatures, contact Microsoft, access Windows Update, or independently validate error codes. A result marked GOOD means that the supplied text contains favorable evidence; it is not an independent health certification.
      </p>
    </details>
  `;
}

function renderPackages(packages) {
  if (!packages.length) return '';
  return `
    <h3>Packages</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Package</th>
            <th>State</th>
            <th>Release type</th>
            <th>Install time</th>
          </tr>
        </thead>
        <tbody>
          ${packages.map(pkg => `
            <tr>
              <td class="mono">${escapeHtml(pkg.identity)}</td>
              <td>${renderStateBadge(classifyPackageState(pkg.state), pkg.state || 'Unknown')}</td>
              <td>${escapeHtml(pkg.releaseType || '—')}</td>
              <td>${escapeHtml(pkg.installTime || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderFeatures(features) {
  if (!features.length) return '';
  return `
    <h3>Features</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Feature</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          ${features.map(feature => `
            <tr>
              <td class="mono">${escapeHtml(feature.name)}</td>
              <td>${escapeHtml(feature.state || 'Unknown')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}
function renderCapabilities(capabilities) {
  if (!capabilities.length) return '';

  return `
    <h3>Capabilities</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Capability</th>
            <th>State</th>
            <th>Download</th>
            <th>Install</th>
          </tr>
        </thead>
        <tbody>
          ${capabilities.map(capability => `
            <tr>
              <td class="mono">${escapeHtml(capability.identity)}</td>
              <td>${escapeHtml(capability.state || 'Unknown')}</td>
              <td>${escapeHtml(capability.downloadSize || '—')}</td>
              <td>${escapeHtml(capability.installSize || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderDrivers(drivers) {
  if (!drivers.length) return '';

  return `
    <h3>Drivers</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Published name</th>
            <th>Provider</th>
            <th>Class</th>
            <th>Version</th>
            <th>Signer</th>
          </tr>
        </thead>
        <tbody>
          ${drivers.map(driver => `
            <tr>
              <td class="mono">${escapeHtml(driver.publishedName || '—')}</td>
              <td>${escapeHtml(driver.providerName || '—')}</td>
              <td>${escapeHtml(driver.className || '—')}</td>
              <td>${escapeHtml(driver.version || '—')}</td>
              <td>${escapeHtml(driver.signerName || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderComponentStore(store) {
  if (!store.detected) return '';

  return `
    <h3>Component store</h3>
    <div class="grid">
      ${stat('Size', store.size || 'Not reported')}
      ${stat('Actual size', store.actualSize || 'Not reported')}
      ${stat('Shared with Windows', store.sharedWithWindows || 'Not reported')}
      ${stat('Backups / disabled features', store.backupsAndDisabledFeatures || 'Not reported')}
      ${stat('Cache / temporary data', store.cacheAndTemporaryData || 'Not reported')}
      ${stat('Corruption', store.corruption || 'Not explicitly reported')}
      ${stat('Repairable', store.repairable || 'Not explicitly reported')}
    </div>
  `;
}

function renderCleanup(cleanup) {
  if (!cleanup.detected) return '';

  return `
    <h3>Component cleanup</h3>
    <div class="grid">
      ${stat('Cleanup detected', cleanup.detected ? 'Yes' : 'No')}
      ${stat('Reclaimable packages', cleanup.reclaimable || 'Not reported')}
      ${stat('Cleanup recommended', cleanup.recommended || 'Not reported')}
      ${stat('ResetBase', cleanup.resetBase ? 'Detected' : 'Not detected')}
    </div>
  `;
}

function renderSource(source) {
  if (!source.detected) return '';

  return `
    <h3>Repair source</h3>
    <div class="status">
      <strong>Source information detected</strong>
      <br>
      <span class="mono">${escapeHtml(
        source.source || 'A repair source parameter was detected.'
      )}</span>
    </div>
  `;}
function renderErrors(errors) {
  if (!errors.length) {
    return `
      <h3>Errors</h3>
      <div class="status success">
        <strong>No explicit DISM error lines detected.</strong>
      </div>
    `;
  }

  return `
    <h3>Errors</h3>
    ${errors.map(error => `
      <div class="status danger">
        <strong>
          ${escapeHtml(error.code || 'Error')}
        </strong>
        <br>
        <span>${escapeHtml(error.text)}</span>
        <div class="small">Line ${error.line}</div>
      </div>
    `).join('')}
  `;
}

function renderWarnings(warnings) {
  if (!warnings.length) return '';

  return `
    <h3>Warnings</h3>
    ${warnings.map(warning => `
      <div class="status warning">
        <strong>Warning</strong>
        <br>
        <span>${escapeHtml(warning.text)}</span>
        <div class="small">Line ${warning.line}</div>
      </div>
    `).join('')}
  `;
}

function renderCommands(commands) {
  if (!commands.length) return '';

  return `
    <h3>Detected commands / switches</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Command / line</th>
          </tr>
        </thead>
        <tbody>
          ${commands.map(command => `
            <tr>
              <td class="mono">${escapeHtml(command)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

function renderObservation(observation) {
  return `
    <div class="status ${statusClass(observation.level)}">
      <strong>
        <span aria-hidden="true" style="font-size:1.15em;margin-right:6px">
          ${statusIcon(observation.level)}
        </span>
        ${escapeHtml(observation.title)}
      </strong>
      <br>
      <span>${escapeHtml(observation.text)}</span>
    </div>
  `;
}

function renderStateBadge(state, text) {
  if (state === 'installed' || state === 'good') {
    return `<span class="status success" style="display:inline-block;padding:3px 7px">${escapeHtml(text)}</span>`;
  }

  if (state === 'pending' || state === 'warn') {
    return `<span class="status warning" style="display:inline-block;padding:3px 7px">${escapeHtml(text)}</span>`;
  }

  if (state === 'bad') {
    return `<span class="status danger" style="display:inline-block;padding:3px 7px">${escapeHtml(text)}</span>`;
  }

  return escapeHtml(text);
}

function bindExports(a) {
  $('#dismExportJson').onclick = () => {
    downloadText(
      'dism-analysis.json',
      JSON.stringify(sanitizeExport(a), null, 2),
      'application/json;charset=utf-8'
    );
  };

  $('#dismExportText').onclick = () => {
    downloadText(
      'dism-analysis.txt',
      buildTextExport(a),
      'text/plain;charset=utf-8'
    );
  };
}

function sanitizeExport(a) {
  return {
    note:
      'Local DISM output analysis only. DISM was not executed and no external validation was performed.',
    summary: a.summary,
    operation: a.operation,
    version: a.version,
    health: a.health,
    result: a.result,
    image: a.image,
    packages: a.packages,
    features: a.features,
    capabilities: a.capabilities,
    drivers: a.drivers,
    cleanup: a.cleanup,
    componentStore: a.componentStore,
    errors: a.errors,
    warnings: a.warnings,
    reboot: a.reboot,
    progress: a.progress,
    source: a.source,
    commands: a.commands,
    observations: a.observations,
    counts: a.counts
  };
}

function buildTextExport(a) {
  const lines = [
    'DISM ANALYSIS',
    '==============',
    '',
    `Summary: ${a.summary.title}`,
    a.summary.text,
    '',
    `DISM version: ${a.version.dismVersion || 'Not found'}`,
    `Image version: ${a.version.imageVersion || 'Not found'}`,
    `Image build: ${a.version.build || 'Not found'}`,
    `Architecture: ${a.image.architecture || 'Not found'}`,
    `Operation: ${a.operation.join(', ')}`,
    '',
    `Component store: ${a.health.label}`,
    `Operation result: ${a.result.label}`,
    `Restart required: ${a.reboot.required ? 'Yes' : 'No'}`,
    ''
  ];

  if (a.errors.length) {
    lines.push('ERRORS');
    lines.push('------');

    for (const error of a.errors) {
      lines.push(
        `Line ${error.line}: ${error.code || 'ERROR'} — ${error.text}`
      );
    }

    lines.push('');
  }

  if (a.warnings.length) {
    lines.push('WARNINGS');
    lines.push('--------');

    for (const warning of a.warnings) {
      lines.push(
        `Line ${warning.line}: ${warning.text}`
      );
    }

    lines.push('');
  }

  if (a.observations.length) {
    lines.push('INTERPRETATION');
    lines.push('--------------');

    for (const observation of a.observations) {
      lines.push(
        `${observation.level.toUpperCase()}: ${observation.title} — ${observation.text}`
      );
    }

    lines.push('');
  }

  if (a.packages.length) {
    lines.push('PACKAGES');
    lines.push('--------');

    for (const pkg of a.packages) {
      lines.push(
        `${pkg.identity} | ${pkg.state || 'Unknown'}`
      );
    }

    lines.push('');
  }

  if (a.features.length) {
    lines.push('FEATURES');
    lines.push('--------');

    for (const feature of a.features) {
      lines.push(
        `${feature.name} | ${feature.state || 'Unknown'}`
      );
    }

    lines.push('');
  }

  if (a.drivers.length) {
    lines.push('DRIVERS');
    lines.push('-------');

    for (const driver of a.drivers) {
      lines.push(
        `${driver.publishedName || 'Unknown'} | ${driver.providerName || ''} | ${driver.version || ''}`
      );
    }

    lines.push('');
  }

  return lines.join('\n');
}

function classifyPackageState(state) {
  const value = String(state || '').toLowerCase();

  if (
    /installed|installiert|enabled|aktiviert/.test(value)
  ) {
    return 'installed';
  }

  if (
    /pending|ausstehend|staged|bereitgestellt|install pending/.test(value)
  ) {
    return 'pending';
  }

  if (
    /superseded|ersetzt|obsolete/.test(value)
  ) {
    return 'superseded';
  }

  if (
    /failed|error|fehler/.test(value)
  ) {
    return 'bad';
  }

  return 'unknown';
}

function assignIfMatch(object, key, text, regex) {
  const match = text.match(regex);

  if (match) {
    object[key] = match[1].trim();
    return true;
  }

  return false;
}

function containsAny(text, patterns) {
  return patterns.some(pattern => text.includes(pattern));
}

function dedupeBy(items, keyFn) {
  const seen = new Set();
  const result = [];

  for (const item of items) {
    const key = keyFn(item);

    if (seen.has(key)) continue;

    seen.add(key);
    result.push(item);
  }

  return result;
}

function stat(label, value) {
  return `
    <div class="stat">
      <span>${escapeHtml(label)}</span>
      <strong style="word-break:break-word">
        ${escapeHtml(value)}
      </strong>
    </div>
  `;
}

function healthStat(label, state, value) {
  return `
    <div class="stat">
      <span>${escapeHtml(label)}</span>
      <strong>
        <span aria-hidden="true" style="margin-right:6px">
          ${statusIcon(state)}
        </span>
        ${escapeHtml(value)}
      </strong>
    </div>
  `;
}

function statusClass(state) {
  if (state === 'good') return 'success';
  if (state === 'bad') return 'danger';
  if (state === 'warn') return 'warning';
  return '';
}

function statusIcon(state) {
  if (state === 'good') return '&#10003;';
  if (state === 'bad') return '&#10007;';
  if (state === 'warn') return '&#9888;';
  return '&#8212;';
}


const EXAMPLE_DISM_OUTPUT = `Deployment Image Servicing and Management tool
Version: 10.0.26100.1

Image Version: 10.0.26100.1742

[==========================100.0%==========================]

No component store corruption detected.
The operation completed successfully.`;