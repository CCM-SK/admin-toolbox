import {
  $,
  escapeHtml,
  downloadText,
  enableToolDragging
} from '../utils.js';
export const metadata = {
  id: 'jsonviewer',
  title: 'JSON Viewer',
  description: 'Render and explore JSON data locally',
  path: '/#jsonviewer'
};
export function renderJsonViewer(app) {
  app.innerHTML = `
    <div class="tool-window" id="jsonViewerWindow">
      <div class="tool-window-header" id="jsonViewerDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>JSON Viewer</strong>
      </div>
      <div class="tool-toolbar">
        <div class="dropzone" id="jsonDrop">
          Drop a JSON file here, or
          <button class="btn" id="jsonPick">choose file</button>
          <input id="jsonViewerFile" type="file" accept=".json,application/json,text/json" hidden>
        </div>
        <button class="btn" id="jsonViewerLoadExample">Load example</button>
        <button class="btn" id="jsonViewerClear">Clear</button>
      </div>
      <div class="tool-section">
        <label for="jsonViewerInput">
          <strong>JSON input</strong>
        </label>
        <textarea
          id="jsonViewerInput"
          rows="12"
          spellcheck="false"
          placeholder="Paste JSON here or load a .json file..."
        ></textarea>
        <div class="tool-toolbar">
          <button class="btn primary" id="jsonViewerAnalyze">Render JSON</button>
          <button class="btn" id="jsonViewerFormat">Format JSON</button>
        </div>
      </div>
      <div id="jsonViewerStatus"></div>
      <div id="jsonViewerControls" hidden>
        <div class="tool-toolbar">
          <button class="btn" id="jsonViewerExpandAll">Expand all</button>
          <button class="btn" id="jsonViewerCollapseAll">Collapse all</button>
          <label>
            <span>Search</span>
            <input
              type="search"
              id="jsonViewerSearch"
              placeholder="Search keys and values..."
            >
          </label>
        </div>
        <div id="jsonViewerStats"></div>
      </div>
      <div
        id="jsonViewerResult"
        class="json-viewer-result"
        aria-live="polite"
      ></div>
      <div id="jsonViewerActions" hidden>
        <div class="tool-toolbar">
          <button type="button" id="jsonViewerCopy">
            Copy formatted JSON
          </button>
          <button type="button" id="jsonViewerDownload">
            Download formatted JSON
          </button>
        </div>
      </div>
    </div>
  `;
  enableToolDragging(
    $('#jsonViewerWindow'),
    $('#jsonViewerDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
  const input = $('#jsonViewerInput');
  const fileInput = $('#jsonViewerFile');
  const result = $('#jsonViewerResult');
  const status = $('#jsonViewerStatus');
  const controls = $('#jsonViewerControls');
  const actions = $('#jsonViewerActions');
  const stats = $('#jsonViewerStats');
  const searchInput = $('#jsonViewerSearch');
  let parsedJson = null;
  let formattedJson = '';
  let nodeCounter = 0;
  $('#jsonViewerAnalyze').addEventListener('click', () => {
    analyzeJson();
  });
  $('#jsonViewerFormat').addEventListener('click', () => {
    formatJson();
  });
  $('#jsonViewerClear').addEventListener('click', () => {
    input.value = '';
    fileInput.value = '';
    searchInput.value = '';
    parsedJson = null;
    formattedJson = '';
    nodeCounter = 0;
    result.innerHTML = '';
    status.innerHTML = '';
    stats.innerHTML = '';
    controls.hidden = true;
    actions.hidden = true;
  });
  $('#jsonViewerLoadExample').addEventListener('click', () => {
    input.value = JSON.stringify(createExampleJson(), null, 2);
    analyzeJson();
  });
  fileInput.addEventListener('change', async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      input.value = text;
      analyzeJson();
    } catch (error) {
      showError(`Unable to read file: ${error.message}`);
    }
  });
  $('#jsonViewerExpandAll').addEventListener('click', () => {
    setAllNodesExpanded(true);
  });
  $('#jsonViewerCollapseAll').addEventListener('click', () => {
    setAllNodesExpanded(false);
  });
  $('#jsonViewerCopy').addEventListener('click', async () => {
    if (!formattedJson) return;
    try {
      await navigator.clipboard.writeText(formattedJson);
      showStatus('Formatted JSON copied to the clipboard.', 'success');
    } catch {
      showError('Unable to copy to the clipboard.');
    }
  });
  $('#jsonViewerDownload').addEventListener('click', () => {
    if (!formattedJson) return;
    downloadText(
      'formatted.json',
      formattedJson,
      'application/json;charset=utf-8'
    );
  });
  searchInput.addEventListener('input', () => {
    applySearch(searchInput.value);
  });
  function analyzeJson() {
    const text = input.value.trim();
    if (!text) {
      showError('Please paste JSON or load a JSON file first.');
      return;
    }
    try {
      parsedJson = JSON.parse(text);
      formattedJson = JSON.stringify(parsedJson, null, 2);
      nodeCounter = 0;
      renderTree(parsedJson);
      renderStats(parsedJson);
      controls.hidden = false;
      actions.hidden = false;
      showStatus('JSON parsed successfully.', 'success');
    } catch (error) {
      parsedJson = null;
      formattedJson = '';
      result.innerHTML = '';
      stats.innerHTML = '';
      controls.hidden = true;
      actions.hidden = true;
      showError(formatJsonError(error));
    }
  }
  function formatJson() {
    const text = input.value.trim();
    if (!text) {
      showError('Please paste JSON or load a JSON file first.');
      return;
    }
    try {
      const parsed = JSON.parse(text);
      input.value = JSON.stringify(parsed, null, 2);
      parsedJson = parsed;
      formattedJson = input.value;
      nodeCounter = 0;
      renderTree(parsed);
      renderStats(parsed);
      controls.hidden = false;
      actions.hidden = false;
      showStatus('JSON formatted successfully.', 'success');
    } catch (error) {
      showError(formatJsonError(error));
    }
  }
  function renderTree(value) {
    result.innerHTML = '';
    const root = document.createElement('div');
    root.className = 'json-tree';
    const treeNode = createNode(
      value,
      null,
      null,
      true,
      true
    );
    if (treeNode) {
      root.appendChild(treeNode);
    }
    result.appendChild(root);
  }
    function createNode(
    value,
    key,
    parent,
    expanded = true,
    isRoot = false,
    depth = 0
    ) {
    const type = getJsonType(value);
    if (type === 'object' || type === 'array') {
      return createContainerNode(
        value,
        key,
        parent,
        expanded,
        isRoot,
        depth
        );
    }
    return createValueNode(
        value,
        key,
        type,
        parent,
        isRoot,
        depth
        );
  }
  function createContainerNode(
    value,
    key,
    parent,
    expanded,
    isRoot,
    depth
    ) {
    const type = Array.isArray(value) ? 'array' : 'object';
    const entries = Array.isArray(value)
      ? value.map((item, index) => [index, item])
      : Object.entries(value);
    const nodeId = `jsonViewerNode${++nodeCounter}`;
    const wrapper = document.createElement('div');
    const depthClass = Math.min(depth, 10);
    wrapper.className = `json-tree-node json-tree-container json-tree-depth-${depthClass}`;
    wrapper.dataset.nodeId = nodeId;
    const header = document.createElement('div');
    header.className = 'json-tree-node-header';
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'json-tree-toggle';
    toggle.setAttribute('aria-expanded', String(expanded));
    toggle.setAttribute('aria-label', expanded ? 'Collapse' : 'Expand');
    toggle.textContent = expanded ? '▼' : '▶';
    const label = document.createElement('span');
    label.className = 'json-tree-label';
    if (isRoot) {
      label.innerHTML = `
        <span class="json-tree-type">${type === 'array' ? '[Array]' : '{Object}'}</span>
        <span class="json-tree-meta">
          ${entries.length} ${entries.length === 1 ? 'item' : 'items'}
        </span>
      `;
    } else {
      const safeKey = escapeHtml(String(key));
      label.innerHTML = `
        <span class="json-tree-key">${safeKey}</span>
        <span class="json-tree-separator">:</span>
        <span class="json-tree-type">
          ${type === 'array' ? '[Array]' : '{Object}'}
        </span>
        <span class="json-tree-meta">
          ${entries.length} ${entries.length === 1 ? 'item' : 'items'}
        </span>
      `;
    }
    header.appendChild(toggle);
    header.appendChild(label);
    const children = document.createElement('div');
    children.className = 'json-tree-children';
    if (!expanded) {
      children.hidden = true;
    }
    for (const [childKey, childValue] of entries) {
      const childNode = createNode(
        childValue,
        childKey,
        value,
        true,
        false,
        depth + 1
        );
      if (childNode) {
        children.appendChild(childNode);
      }
    }
    toggle.addEventListener('click', () => {
      const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
      const nextState = !isExpanded;
      toggle.setAttribute('aria-expanded', String(nextState));
      toggle.setAttribute(
        'aria-label',
        nextState ? 'Collapse' : 'Expand'
      );
      toggle.textContent = nextState ? '▼' : '▶';
      children.hidden = !nextState;
    });
    wrapper.appendChild(header);
    wrapper.appendChild(children);
    return wrapper;
  }
  function createValueNode(
    value,
    key,
    type,
    parent,
    isRoot,
    depth
    ) {
    const wrapper = document.createElement('div');
    const depthClass = Math.min(depth, 10);
    wrapper.className = `json-tree-node json-tree-value json-tree-depth-${depthClass}`;
    const content = document.createElement('div');
    content.className = 'json-tree-value-content';
    if (!isRoot) {
      const keyElement = document.createElement('span');
      keyElement.className = 'json-tree-key';
      keyElement.textContent = String(key);
      const separator = document.createElement('span');
      separator.className = 'json-tree-separator';
      separator.textContent = ':';
      content.appendChild(keyElement);
      content.appendChild(separator);
    }
    const valueElement = document.createElement('span');
    valueElement.className = `json-tree-value-${type}`;
    if (type === 'string') {
      valueElement.textContent = `"${value}"`;
    } else if (type === 'null') {
      valueElement.textContent = 'null';
    } else {
      valueElement.textContent = String(value);
    }
    content.appendChild(valueElement);
    wrapper.appendChild(content);
    return wrapper;
  }
  function renderStats(value) {
    const statistics = calculateStats(value);
    stats.innerHTML = `
      <div class="json-viewer-stats">
        <div class="json-viewer-stat">
          <strong>${statistics.objects}</strong>
          <span>Objects</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.arrays}</strong>
          <span>Arrays</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.properties}</strong>
          <span>Properties</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.values}</strong>
          <span>Values</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.strings}</strong>
          <span>Strings</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.numbers}</strong>
          <span>Numbers</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.booleans}</strong>
          <span>Booleans</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.nulls}</strong>
          <span>Nulls</span>
        </div>
        <div class="json-viewer-stat">
          <strong>${statistics.maxDepth}</strong>
          <span>Max depth</span>
        </div>
      </div>
    `;
  }
  function calculateStats(value, depth = 0, statistics = null) {
    if (!statistics) {
      statistics = {
        objects: 0,
        arrays: 0,
        properties: 0,
        values: 0,
        strings: 0,
        numbers: 0,
        booleans: 0,
        nulls: 0,
        maxDepth: 0
      };
    }
    statistics.maxDepth = Math.max(
      statistics.maxDepth,
      depth
    );
    if (Array.isArray(value)) {
      statistics.arrays++;
      for (const item of value) {
        statistics.properties++;
        calculateStats(item, depth + 1, statistics);
      }
      return statistics;
    }
    if (value !== null && typeof value === 'object') {
      statistics.objects++;
      for (const [key, child] of Object.entries(value)) {
        void key;
        statistics.properties++;
        calculateStats(child, depth + 1, statistics);
      }
      return statistics;
    }
    statistics.values++;
    if (typeof value === 'string') {
      statistics.strings++;
    } else if (typeof value === 'number') {
      statistics.numbers++;
    } else if (typeof value === 'boolean') {
      statistics.booleans++;
    } else if (value === null) {
      statistics.nulls++;
    }
    return statistics;
  }
  function setAllNodesExpanded(expanded) {
    const toggles = result.querySelectorAll(
      '.json-tree-container > .json-tree-node-header > .json-tree-toggle'
    );
    for (const toggle of toggles) {
      toggle.setAttribute(
        'aria-expanded',
        String(expanded)
      );
      toggle.setAttribute(
        'aria-label',
        expanded ? 'Collapse' : 'Expand'
      );
      toggle.textContent = expanded ? '▼' : '▶';
      const container = toggle.closest('.json-tree-container');
      if (!container) continue;
      const children = container.querySelector(
        ':scope > .json-tree-children'
      );
      if (children) {
        children.hidden = !expanded;
      }
    }
  }
  function applySearch(searchTerm) {
    const term = searchTerm.trim().toLowerCase();
    const nodes = result.querySelectorAll(
      '.json-tree-node'
    );
    if (!term) {
      for (const node of nodes) {
        node.hidden = false;
      }
      return;
    }
    for (const node of nodes) {
      node.hidden = false;
    }
    for (const node of nodes) {
      if (nodeMatchesSearch(node, term)) {
        continue;
      }
      const descendants = node.querySelectorAll(
        '.json-tree-node'
      );
      let descendantMatches = false;
      for (const descendant of descendants) {
        if (nodeMatchesSearch(descendant, term)) {
          descendantMatches = true;
          break;
        }
      }
      if (!descendantMatches) {
        node.hidden = true;
      }
    }
    expandParentsOfMatches(term);
  }
  function nodeMatchesSearch(node, term) {
    const text = node.textContent
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase();
    return text.includes(term);
  }
  function expandParentsOfMatches(term) {
    const nodes = result.querySelectorAll(
      '.json-tree-node'
    );
    for (const node of nodes) {
      if (!nodeMatchesSearch(node, term)) continue;
      let parent = node.parentElement;
      while (parent) {
        if (parent.classList.contains('json-tree-container')) {
          const toggle = parent.querySelector(
            ':scope > .json-tree-node-header > .json-tree-toggle'
          );
          const children = parent.querySelector(
            ':scope > .json-tree-children'
          );
          if (toggle && children) {
            toggle.setAttribute('aria-expanded', 'true');
            toggle.setAttribute('aria-label', 'Collapse');
            toggle.textContent = '▼';
            children.hidden = false;
          }
        }
        parent = parent.parentElement;
      }
    }
  }
  function getJsonType(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) {
      return 'array';
    }
    return typeof value;
  }
  function formatJsonError(error) {
    if (!error) {
      return 'Invalid JSON.';
    }
    const message = error.message || String(error);
    return `Invalid JSON: ${message}`;
  }
  function showStatus(message, type = 'info') {
    status.innerHTML = `
      <div class="tool-status tool-status-${escapeHtml(type)}">
        ${escapeHtml(message)}
      </div>
    `;
  }
  function showError(message) {
    status.innerHTML = `
      <div class="tool-status tool-status-error">
        ${escapeHtml(message)}
      </div>
    `;
  }
  function createExampleJson() {
    return [
      {
        Software: '--',
        Versions:
          'Inventoried (3919) [], 7.2.0.09 (1) [Inventoried], 7.2.0.08 (1) [Inventoried]'
      },
      {
        Software: 'Auto Dark Mode',
        Versions: '11 (1) [Installed]'
      },
      {
        Software: 'ITK-SNAP',
        Versions: '0.1.1 (6) [Inventoried]'
      },
      {
        Software: '.Net Core',
        Versions:
          '8.0.31-x86 (16) [ManagedSoftware], 8.0.31-x64 (62) [ManagedSoftware]'
      },
      {
        Software: 'Nested example',
        Versions: {
          Installed: true,
          Count: 3,
          Details: [
            {
              Name: 'Example Application',
              Version: '1.0.0',
              Platforms: ['x64', 'ARM64']
            },
            {
              Name: 'Another Application',
              Version: '2.5.1',
              Metadata: {
                Source: 'ManagedSoftware',
                Active: true,
                Tags: [
                  'example',
                  'nested',
                  'json'
                ]
              }
            }
          ]
        }
      }
    ];
  }
}