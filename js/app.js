import { TOOL_REGISTRY, TOOL_BY_ID } from './registry.js';
import { addWorkflowArtifact, clearWorkflow, getWorkflowArtifact, listWorkflowArtifacts, removeWorkflowArtifact, replaceWorkflowArtifacts } from './workflow.js';
import { downloadText, enableToolDragging, escapeHtml, formatBytes, setActiveToolScope } from './utils.js';
import { createCanvasLayoutExport, displaySpaceName, parseCanvasLayoutExport, resolveCanvasPanelDimensions, sortToolsBySpaceThenName } from './canvas-layout.js';

const app = document.querySelector('#app');
const navRoot = document.querySelector('#toolNavigation');
const searchInput = document.querySelector('#toolSearch');
const searchResults = document.querySelector('#toolSearchResults');
const actionBar = document.querySelector('#toolActionBar');
const workspaceDialog = document.querySelector('#workspaceDialog');
const workCanvasView = document.querySelector('#workCanvasView');
const canvasBoard = document.querySelector('#workCanvasBoard');
const canvasToolPicker = document.querySelector('#canvasToolPicker');
const MAX_CANVAS_PANELS = 16;
const CANVAS_EMPTY_HINT = 'Add a tool to get started. You can open several different tools and work in them side by side.';
const favorites = new Set();
let recentTools = [];
let currentToolId = 'dashboard';
let activationVersion = 0;
let canvasMode = false;
let sidebarCollapsedBeforeCanvas = false;
let canvasZIndex = 20;
const canvasPanels = new Map();
const MAX_WORKSPACE_FILE_BYTES = 64 * 1024 * 1024;

function iconFor(tool) {
  const icons = {
    Diagnostics: '▤', 'Security & identity': '◈', 'Network & firewall': '⌘',
    'Developer & data': '⌘', 'Windows & hardware': '▣', Automation: '⟳',
    Administration: '✓', Home: '⌂'
  };
  return icons[tool.category] || '◦';
}
function toolButton(tool, extraClass = '') {
  const isFavorite = favorites.has(tool.id);
  return `<div class="nav-entry">
    <button type="button" class="nav-item ${extraClass}" data-tool="${escapeHtml(tool.id)}" aria-current="${tool.id === currentToolId ? 'page' : 'false'}">
      <span class="nav-icon" aria-hidden="true">${iconFor(tool)}</span><span>${escapeHtml(tool.name)}</span>
    </button>
    <button type="button" class="nav-favorite" data-favorite="${escapeHtml(tool.id)}" aria-label="${isFavorite ? 'Remove from' : 'Add to'} favorites: ${escapeHtml(tool.name)}" aria-pressed="${isFavorite}">${isFavorite ? '★' : '☆'}</button>
  </div>`;
}
function renderShortcutSection(sectionId, listId, ids) {
  const section = document.querySelector(`#${sectionId}`);
  const target = document.querySelector(`#${listId}`);
  const tools = ids.map(id => TOOL_BY_ID.get(id)).filter(Boolean);
  section.hidden = !tools.length;
  target.innerHTML = tools.map(tool => toolButton(tool)).join('');
}
function renderNavigation() {
  const home = TOOL_BY_ID.get('dashboard');
  const audit = TOOL_BY_ID.get('audit');
  const groups = [...new Set(TOOL_REGISTRY.map(t => t.category).filter(c => !['Home', 'Administration'].includes(c)))];
  navRoot.innerHTML = toolButton(home, 'nav-home') + groups.map(category => {
    const tools = TOOL_REGISTRY.filter(t => t.category === category);
    return `<details class="tool-group" data-category="${escapeHtml(category)}" open>
      <summary><span class="group-icon">${iconFor({ category })}</span><span>${escapeHtml(category)}</span></summary>
      <div class="group-items">${tools.map(tool => toolButton(tool)).join('')}</div>
    </details>`;
  }).join('');
  const auditButton = document.querySelector('.sidebar-footer [data-tool="audit"]');
  if (auditButton && audit) auditButton.setAttribute('aria-label', audit.name);
  renderShortcutSection('toolFavoritesSection', 'toolFavorites', [...favorites]);
  renderShortcutSection('toolRecentSection', 'toolRecent', recentTools.slice(0, 6));
  wireNavButtons(navRoot);
  wireNavButtons(document.querySelector('#toolFavorites'));
  wireNavButtons(document.querySelector('#toolRecent'));
  wireNavButtons(document.querySelector('.sidebar-footer'));
}
function wireNavButtons(root) {
  root?.querySelectorAll('[data-tool]').forEach(button => {
    button.onclick = () => { setCanvasMode(false); activate(button.dataset.tool); };
  });
  root?.querySelectorAll('[data-favorite]').forEach(button => {
    button.onclick = event => {
      event.stopPropagation();
      const id = button.dataset.favorite;
      if (favorites.has(id)) favorites.delete(id); else favorites.add(id);
      renderNavigation();
    };
  });
}
function recordRecentTool(id) {
  if (!id || id === 'dashboard') return;
  recentTools = [id, ...recentTools.filter(item => item !== id)].slice(0, 10);
  renderNavigation();
  updateActiveNavigation();
}
function updateActiveNavigation() {
  document.querySelectorAll('.nav-item[data-tool]').forEach(button => {
    const active = button.dataset.tool === currentToolId;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.setAttribute('aria-current', 'false');
  });
  const activeButton = document.querySelector(`.nav-item[data-tool="${CSS.escape(currentToolId)}"]`);
  const group = activeButton?.closest('.tool-group');
  if (group) group.open = true;
}
function renderSearchResults() {
  const query = searchInput.value.trim().toLocaleLowerCase();
  if (!query) { searchResults.hidden = true; searchResults.innerHTML = ''; return; }
  const matches = TOOL_REGISTRY.filter(tool => `${tool.name} ${tool.category} ${tool.description} ${tool.id}`.toLocaleLowerCase().includes(query)).slice(0, 20);
  searchResults.innerHTML = matches.length
    ? matches.map(tool => `<button type="button" class="tool-search-result" data-tool="${escapeHtml(tool.id)}"><span><strong>${escapeHtml(tool.name)}</strong><small>${escapeHtml(tool.category)} · ${escapeHtml(tool.description)}</small></span></button>`).join('')
    : '<p class="small">No matching tools.</p>';
  searchResults.hidden = false;
  wireNavButtons(searchResults);
}
searchInput.addEventListener('input', renderSearchResults);
searchInput.addEventListener('keydown', event => {
  if (event.key === 'Enter') searchResults.querySelector('[data-tool]')?.click();
  if (event.key === 'Escape') { searchInput.value = ''; renderSearchResults(); searchInput.blur(); }
});
document.addEventListener('keydown', event => {
  const target = event.target;
  const editing = target instanceof HTMLElement && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault(); searchInput.focus(); searchInput.select();
  } else if (event.key === '/' && !editing && !event.ctrlKey && !event.metaKey && !event.altKey) {
    event.preventDefault(); searchInput.focus();
  }
});

function updateToolbar(tool) {
  actionBar.hidden = canvasMode || tool.id === 'dashboard';
  document.querySelector('#activeToolName').textContent = tool.name;
  document.querySelector('#activeToolCategory').textContent = tool.category;
  document.querySelector('#toolActionMessage').textContent = '';
  const exampleButton = document.querySelector('#loadToolExample');
  exampleButton.hidden = !tool.example;
  document.querySelector('#addToWorkflow').hidden = !tool.workflowSource;
  document.querySelector('#openInCanvas').hidden = tool.id === 'dashboard';
}
function showToolMessage(message, kind = '') {
  const el = document.querySelector('#toolActionMessage');
  el.textContent = message;
  el.dataset.kind = kind;
}
function initializeToolDragging(tool) {
  // Most tools render a single .tool-window themselves. Wrap the remaining
  // tools so every registered tool gets the same draggable title bar.
  let toolWindow = app.children.length === 1 && app.firstElementChild?.classList.contains('tool-window')
    ? app.firstElementChild
    : null;

  if (!toolWindow) {
    toolWindow = document.createElement('div');
    toolWindow.className = 'tool-window tool-window--generated';
    toolWindow.dataset.toolId = tool.id;
    const content = document.createDocumentFragment();
    while (app.firstChild) content.append(app.firstChild);
    toolWindow.append(content);
    app.append(toolWindow);
  }

  let dragHandle = toolWindow.querySelector(':scope > .tool-window-header');
  if (!dragHandle) {
    dragHandle = document.createElement('div');
    dragHandle.className = 'tool-window-header tool-window-header--generated';
    dragHandle.title = 'Detach the sidebar, then drag to move this tool';
    const grip = document.createElement('span');
    grip.className = 'tool-drag-grip';
    grip.setAttribute('aria-hidden', 'true');
    grip.textContent = '⋮⋮';
    const title = document.createElement('strong');
    title.textContent = tool.name;
    dragHandle.append(grip, title);
    toolWindow.prepend(dragHandle);
  } else if (!dragHandle.title) {
    dragHandle.title = 'Detach the sidebar, then drag to move this tool';
  }

  // Existing tool modules may already initialize their own drag handle.
  // enableToolDragging is idempotent, so this safely covers both cases.
  enableToolDragging(
    toolWindow,
    dragHandle,
    () => document.body.classList.contains('sidebar-detached')
  );
}

function setSidebarCollapsed(collapsed) {
  const next = Boolean(collapsed);
  document.body.classList.toggle('sidebar-collapsed', next);
  const toggle = document.querySelector('#sidebarToggle');
  toggle?.setAttribute('aria-expanded', String(!next));
  toggle?.setAttribute('aria-label', next ? 'Expand tool sidebar' : 'Collapse tool sidebar');
  if (toggle) {
    toggle.title = next ? 'Expand tool sidebar' : 'Collapse tool sidebar';
    const label = toggle.querySelector('.button-label');
    if (label) label.textContent = next ? 'Show tools' : 'Hide tools';
  }
  if (canvasMode) requestAnimationFrame(updateCanvasBoardExtent);
}

document.querySelector('#sidebarToggle').addEventListener('click', () => {
  setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed'));
});

function setCanvasMode(enabled, { seedCurrentTool = false } = {}) {
  const nextMode = Boolean(enabled);
  if (nextMode && !canvasMode) {
    sidebarCollapsedBeforeCanvas = document.body.classList.contains('sidebar-collapsed');
    setSidebarCollapsed(true);
  } else if (!nextMode && canvasMode) {
    setSidebarCollapsed(sidebarCollapsedBeforeCanvas);
  }
  canvasMode = nextMode;
  document.body.classList.toggle('work-canvas-active', canvasMode);
  workCanvasView.hidden = !canvasMode;
  app.hidden = canvasMode;
  actionBar.hidden = canvasMode || currentToolId === 'dashboard';
  if (!canvasMode) setActiveToolScope(app);
  const toggle = document.querySelector('#workCanvasToggle');
  toggle?.setAttribute('aria-pressed', String(canvasMode));
  if (toggle) {
    toggle.title = canvasMode ? 'Return to single-tool view' : 'Open Work Canvas';
    const label = toggle.querySelector('.button-label');
    if (label) label.textContent = canvasMode ? 'Back to Tools' : 'Work Canvas';
  }
  if (canvasMode) {
    requestAnimationFrame(updateCanvasBoardExtent);
    if (seedCurrentTool && currentToolId !== 'dashboard' && canvasPanels.size === 0) {
      void addToolToCanvas(currentToolId);
    }
  }
}

function focusCanvasPanel(panel) {
  if (!panel?.isConnected) return;
  canvasZIndex += 1;
  panel.style.zIndex = String(canvasZIndex);
  canvasBoard.querySelectorAll('.canvas-panel').forEach(item => item.classList.toggle('is-active', item === panel));
  const entry = canvasPanels.get(panel.dataset.toolId);
  if (entry) setActiveToolScope(entry.root);
}

function updateCanvasBoardExtent() {
  if (!canvasBoard || !canvasMode) return;
  const minimum = Math.max(520, Math.floor(window.innerHeight * 0.68));
  let bottom = minimum;
  for (const { panel } of canvasPanels.values()) {
    if (!panel.isConnected) continue;
    const top = Number.parseFloat(panel.style.top) || 0;
    const height = panel.classList.contains('is-minimized')
      ? 48
      : (Number.parseFloat(panel.style.height) || panel.offsetHeight || 500);
    bottom = Math.max(bottom, top + height + 28);
  }
  canvasBoard.style.minHeight = `${bottom}px`;
}

function makeCanvasAction(label, title, handler, className = 'btn') {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.title = title;
  button.addEventListener('click', handler);
  return button;
}

function applyExampleToRoot(tool, root, status) {
  if (!tool?.example) return;
  try {
    for (const field of tool.example.values || []) {
      const input = root.querySelector(field.selector);
      if (!input) throw new Error(`Example target ${field.selector} was not found in this tool.`);
      input.value = field.value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (tool.example.runSelector) {
      const run = root.querySelector(tool.example.runSelector);
      if (!run) throw new Error(`Example action ${tool.example.runSelector} was not found.`);
      run.click();
    }
    status.textContent = 'Example loaded. Review or edit the sample before using it.';
    status.dataset.kind = 'success';
  } catch (error) {
    status.textContent = error.message || 'Unable to load example.';
    status.dataset.kind = 'error';
  }
}

function addRootInputToWorkflow(tool, root, status) {
  if (!tool?.workflowSource) return;
  const value = root.dataset.workflowText || root.querySelector(tool.workflowSource)?.value || '';
  try {
    const item = addWorkflowArtifact({ name: `${tool.name} input`, source: tool.name, content: value, contentType: 'text/plain' });
    status.textContent = `Added “${item.name}” to workflow (${formatBytes(item.bytes)}).`;
    status.dataset.kind = 'success';
  } catch (error) {
    status.textContent = error.message || 'Unable to add workflow input.';
    status.dataset.kind = 'error';
  }
}

function wireCanvasWindow(panel, tool, root, main, status) {
  const header = panel.querySelector('.canvas-panel-header');
  const minimizeButton = panel.querySelector('[data-canvas-minimize]');
  const maximizeButton = panel.querySelector('[data-canvas-maximize]');
  const closeButton = panel.querySelector('[data-canvas-close]');
  const resizeHandle = panel.querySelector('.canvas-panel-resize');

  closeButton.addEventListener('click', () => {
    document.dispatchEvent(new CustomEvent('toolbox:tool-deactivate', { detail: { toolId: tool.id, scope: root } }));
    canvasPanels.delete(tool.id);
    panel.remove();
    const remaining = [...canvasPanels.values()].at(-1);
    if (remaining) focusCanvasPanel(remaining.panel);
    else setActiveToolScope(app);
    updateCanvasBoardExtent();
    const hint = document.querySelector('#canvasHint');
    hint.hidden = canvasPanels.size > 0;
    if (!canvasPanels.size) hint.textContent = CANVAS_EMPTY_HINT;
  });
  minimizeButton.addEventListener('click', () => {
    const minimized = panel.classList.toggle('is-minimized');
    if (minimized) {
      panel.dataset.expandedHeight = panel.style.height || `${panel.offsetHeight}px`;
      panel.style.height = '48px';
      main.hidden = true;
      minimizeButton.textContent = '□';
      minimizeButton.title = 'Restore panel';
      minimizeButton.setAttribute('aria-label', `Restore ${tool.name}`);
    } else {
      panel.style.height = panel.dataset.expandedHeight || '520px';
      main.hidden = false;
      minimizeButton.textContent = '−';
      minimizeButton.title = 'Minimize panel';
      minimizeButton.setAttribute('aria-label', `Minimize ${tool.name}`);
    }
    updateCanvasBoardExtent();
    focusCanvasPanel(panel);
  });
  maximizeButton.addEventListener('click', () => {
    if (panel.classList.contains('is-maximized')) {
      const previous = JSON.parse(panel.dataset.previousRect || '{}');
      panel.style.left = previous.left || '24px';
      panel.style.top = previous.top || '24px';
      panel.style.width = previous.width || '640px';
      panel.style.height = previous.height || '520px';
      panel.classList.remove('is-maximized');
      if (previous.minimized === 'true') {
        panel.querySelector('.canvas-panel-main').hidden = true;
        panel.classList.add('is-minimized');
        panel.style.height = '48px';
        panel.dataset.expandedHeight = previous.height || '520px';
        const minimize = panel.querySelector('[data-canvas-minimize]');
        minimize.textContent = '□';
        minimize.title = 'Restore panel';
      }
      maximizeButton.textContent = '□';
      maximizeButton.title = 'Maximize panel';
      maximizeButton.setAttribute('aria-label', `Maximize ${tool.name}`);
    } else {
      const wasMinimized = panel.classList.contains('is-minimized');
      panel.dataset.previousRect = JSON.stringify({
        left: panel.style.left, top: panel.style.top,
        width: panel.style.width,
        height: wasMinimized ? (panel.dataset.expandedHeight || '520px') : panel.style.height,
        minimized: String(wasMinimized)
      });
      panel.classList.remove('is-minimized');
      main.hidden = false;
      minimizeButton.textContent = '−';
      minimizeButton.title = 'Minimize panel';
      minimizeButton.setAttribute('aria-label', `Minimize ${tool.name}`);
      panel.style.left = '12px';
      panel.style.top = '12px';
      panel.style.width = `${Math.max(320, canvasBoard.clientWidth - 24)}px`;
      panel.style.height = `${Math.max(360, canvasBoard.clientHeight - 24)}px`;
      panel.classList.add('is-maximized');
      maximizeButton.textContent = '❐';
      maximizeButton.title = 'Restore panel size';
      maximizeButton.setAttribute('aria-label', `Restore ${tool.name} size`);
      minimizeButton.textContent = '−';
    }
    updateCanvasBoardExtent();
    focusCanvasPanel(panel);
  });

  let drag = null;
  header.addEventListener('pointerdown', event => {
    if (event.button !== 0 || event.target.closest('button, input, select, textarea, a')) return;
    if (panel.classList.contains('is-maximized')) return;
    focusCanvasPanel(panel);
    drag = {
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      left: Number.parseFloat(panel.style.left) || 0,
      top: Number.parseFloat(panel.style.top) || 0
    };
    header.setPointerCapture(event.pointerId);
    header.classList.add('dragging');
    event.preventDefault();
  });
  header.addEventListener('pointermove', event => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    const maxLeft = Math.max(0, canvasBoard.clientWidth - 72);
    const maxTop = Math.max(0, canvasBoard.scrollHeight - 44);
    panel.style.left = `${Math.max(0, Math.min(maxLeft, drag.left + event.clientX - drag.x))}px`;
    panel.style.top = `${Math.max(0, Math.min(maxTop, drag.top + event.clientY - drag.y))}px`;
    updateCanvasBoardExtent();
  });
  const stopDrag = event => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    drag = null;
    header.classList.remove('dragging');
    try { header.releasePointerCapture(event.pointerId); } catch {}
  };
  header.addEventListener('pointerup', stopDrag);
  header.addEventListener('pointercancel', stopDrag);
  header.addEventListener('keydown', event => {
    if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const delta = event.shiftKey ? 40 : 12;
    const left = Number.parseFloat(panel.style.left) || 0;
    const top = Number.parseFloat(panel.style.top) || 0;
    if (event.key === 'ArrowLeft') panel.style.left = `${Math.max(0, left - delta)}px`;
    if (event.key === 'ArrowRight') panel.style.left = `${Math.min(Math.max(0, canvasBoard.clientWidth - 72), left + delta)}px`;
    if (event.key === 'ArrowUp') panel.style.top = `${Math.max(0, top - delta)}px`;
    if (event.key === 'ArrowDown') panel.style.top = `${top + delta}px`;
    updateCanvasBoardExtent();
  });

  let resize = null;
  resizeHandle.addEventListener('pointerdown', event => {
    if (event.button !== 0 || panel.classList.contains('is-maximized')) return;
    focusCanvasPanel(panel);
    resize = {
      pointerId: event.pointerId, x: event.clientX, y: event.clientY,
      width: panel.offsetWidth, height: panel.offsetHeight
    };
    resizeHandle.setPointerCapture(event.pointerId);
    event.preventDefault();
    event.stopPropagation();
  });
  resizeHandle.addEventListener('pointermove', event => {
    if (!resize || event.pointerId !== resize.pointerId) return;
    panel.style.width = `${Math.max(340, Math.min(canvasBoard.clientWidth - (Number.parseFloat(panel.style.left) || 0) - 12, resize.width + event.clientX - resize.x))}px`;
    panel.style.height = `${Math.max(280, resize.height + event.clientY - resize.y)}px`;
    updateCanvasBoardExtent();
  });
  const stopResize = event => {
    if (!resize || event.pointerId !== resize.pointerId) return;
    resize = null;
    try { resizeHandle.releasePointerCapture(event.pointerId); } catch {}
  };
  resizeHandle.addEventListener('pointerup', stopResize);
  resizeHandle.addEventListener('pointercancel', stopResize);
  resizeHandle.addEventListener('keydown', event => {
    if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const width = Number.parseFloat(panel.style.width) || panel.offsetWidth;
    const height = Number.parseFloat(panel.style.height) || panel.offsetHeight;
    const delta = event.shiftKey ? 40 : 12;
    if (event.key === 'ArrowLeft') panel.style.width = `${Math.max(340, width - delta)}px`;
    if (event.key === 'ArrowRight') panel.style.width = `${Math.min(canvasBoard.clientWidth - (Number.parseFloat(panel.style.left) || 0) - 12, width + delta)}px`;
    if (event.key === 'ArrowUp') panel.style.height = `${Math.max(280, height - delta)}px`;
    if (event.key === 'ArrowDown') panel.style.height = `${height + delta}px`;
    updateCanvasBoardExtent();
  });

  panel.addEventListener('pointerdown', () => focusCanvasPanel(panel));
  panel.addEventListener('focusin', () => setActiveToolScope(root));
  root.querySelectorAll('[data-open-tool]').forEach(button => {
    button.addEventListener('click', () => addToolToCanvas(button.dataset.openTool));
  });
  if (tool.example) {
    const exampleButton = makeCanvasAction('Load example', 'Load the sample input for this tool', () => applyExampleToRoot(tool, root, status));
    panel.querySelector('.canvas-panel-actions').append(exampleButton);
  }
  if (tool.workflowSource) {
    const workflowButton = makeCanvasAction('Add input to workflow', 'Add this tool input to the shared workflow', () => addRootInputToWorkflow(tool, root, status));
    panel.querySelector('.canvas-panel-actions').append(workflowButton);
  }
}

async function addToolToCanvas(id, layout = null) {
  const tool = TOOL_BY_ID.get(id);
  if (!tool) return null;
  setCanvasMode(true);
  const existing = canvasPanels.get(tool.id);
  if (existing) {
    if (existing.panel.classList.contains('is-minimized')) existing.panel.querySelector('[data-canvas-minimize]').click();
    focusCanvasPanel(existing.panel);
    recordRecentTool(tool.id);
    return existing;
  }
  if (canvasPanels.size >= MAX_CANVAS_PANELS) {
    document.querySelector('#canvasHint').textContent = `Work Canvas is limited to ${MAX_CANVAS_PANELS} open tools at once to keep browser performance responsive.`;
    document.querySelector('#canvasHint').hidden = false;
    return null;
  }

  const panel = document.createElement('section');
  panel.className = 'canvas-panel';
  panel.dataset.toolId = tool.id;
  panel.setAttribute('aria-label', `${tool.name} panel`);
  panel.innerHTML = `
    <header class="canvas-panel-header" tabindex="0" aria-label="Move ${escapeHtml(tool.name)} panel. Use arrow keys to move.">
      <span class="canvas-panel-grip" aria-hidden="true">⠿</span>
      <strong></strong>
      <div class="canvas-panel-controls">
        <button class="canvas-window-button" type="button" data-canvas-minimize title="Minimize panel" aria-label="Minimize ${escapeHtml(tool.name)}">−</button>
        <button class="canvas-window-button" type="button" data-canvas-maximize title="Maximize panel" aria-label="Maximize ${escapeHtml(tool.name)}">□</button>
        <button class="canvas-window-button canvas-window-close" type="button" data-canvas-close title="Close panel" aria-label="Close ${escapeHtml(tool.name)}">×</button>
      </div>
    </header>
    <div class="canvas-panel-main">
      <div class="canvas-panel-actions"></div>
      <div class="canvas-panel-status small" role="status" aria-live="polite"></div>
      <div class="canvas-panel-body"><div class="canvas-panel-tool"></div></div>
    </div>
    <button class="canvas-panel-resize" type="button" aria-label="Resize ${escapeHtml(tool.name)} panel" title="Drag to resize; use arrow keys"></button>`;
  panel.querySelector('.canvas-panel-header strong').textContent = tool.name;
  const index = canvasPanels.size;
  const boardWidth = canvasBoard.clientWidth || window.innerWidth - 80;
  const panelWidth = Math.min(680, Math.max(340, boardWidth - 36));
  const columns = boardWidth >= panelWidth * 2 + 72 ? 2 : 1;
  const requestedLeft = layout?.left ?? (24 + (index % columns) * (panelWidth + 20));
  const left = Math.max(0, Math.min(Math.max(0, boardWidth - 72), requestedLeft));
  const top = Math.max(0, Math.min(50000, layout?.top ?? (24 + Math.floor(index / columns) * 42)));
  const dimensions = resolveCanvasPanelDimensions(layout, { width: panelWidth, height: 520 });
  panel.style.left = `${left}px`;
  panel.style.top = `${top}px`;
  // Do not clamp imported widths to the current viewport. Canvas can scroll,
  // and the original window size must survive imports across monitor sizes.
  panel.style.width = `${dimensions.width}px`;
  panel.style.height = `${dimensions.height}px`;
  canvasBoard.append(panel);
  const root = panel.querySelector('.canvas-panel-tool');
  const main = panel.querySelector('.canvas-panel-main');
  const status = panel.querySelector('.canvas-panel-status');
  const entry = { panel, root, tool };
  canvasPanels.set(tool.id, entry);
  wireCanvasWindow(panel, tool, root, main, status);
  focusCanvasPanel(panel);
  document.querySelector('#canvasHint').hidden = true;
  updateCanvasBoardExtent();

  try {
    setActiveToolScope(root);
    const renderer = await tool.load();
    if (!panel.isConnected || canvasPanels.get(tool.id) !== entry) return null;
    setActiveToolScope(root);
    renderer(root);
    root.querySelectorAll('[data-open-tool]').forEach(button => {
      button.onclick = () => addToolToCanvas(button.dataset.openTool);
    });
    setActiveToolScope(root);
    if (layout?.minimized) panel.querySelector('[data-canvas-minimize]').click();
    if (layout?.maximized) panel.querySelector('[data-canvas-maximize]').click();
    recordRecentTool(tool.id);
    updateCanvasBoardExtent();
    return entry;
  } catch (error) {
    if (!panel.isConnected) return null;
    root.innerHTML = `<section class="card"><h2>Unable to load ${escapeHtml(tool.name)}</h2><div class="status danger">${escapeHtml(error.message || 'Tool module failed to load.')}</div><p class="small">Check that this tool module is included in the GitHub Pages deployment.</p></section>`;
    return entry;
  }
}

canvasBoard.addEventListener('pointerdown', event => {
  const panel = event.target.closest('.canvas-panel');
  if (panel) focusCanvasPanel(panel);
}, true);
canvasBoard.addEventListener('focusin', event => {
  const panel = event.target.closest('.canvas-panel');
  const entry = panel && canvasPanels.get(panel.dataset.toolId);
  if (entry) setActiveToolScope(entry.root);
}, true);

document.querySelector('#workCanvasToggle').addEventListener('click', () => {
  if (canvasMode) setCanvasMode(false);
  else setCanvasMode(true, { seedCurrentTool: true });
});
document.querySelector('#canvasAddTool').addEventListener('click', () => {
  if (canvasToolPicker.value) void addToolToCanvas(canvasToolPicker.value);
});
const canvasPickerTools = sortToolsBySpaceThenName(TOOL_REGISTRY.filter(tool => tool.id !== 'dashboard'));
const canvasPickerSpaces = [...new Set(canvasPickerTools.map(tool => tool.category))]
  .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true }));
canvasToolPicker.innerHTML = canvasPickerSpaces.map(space => {
  const options = canvasPickerTools.filter(tool => tool.category === space).map(tool =>
    `<option value="${escapeHtml(tool.id)}">${escapeHtml(tool.name)}</option>`
  ).join('');
  return `<optgroup label="${escapeHtml(displaySpaceName(space))}">${options}</optgroup>`;
}).join('');
window.addEventListener('resize', updateCanvasBoardExtent);

async function activate(id, updateHistory = true, recordRecent = true) {
  const tool = TOOL_BY_ID.get(id) || TOOL_BY_ID.get('dashboard');
  document.dispatchEvent(new CustomEvent('toolbox:tool-deactivate', { detail: { toolId: currentToolId, scope: app } }));
  searchInput.value = '';
  searchResults.hidden = true;
  searchResults.innerHTML = '';
  const version = ++activationVersion;
  currentToolId = tool.id;
  setActiveToolScope(app);
  if (updateHistory) history.pushState(null, '', `#${tool.id}`);
  updateActiveNavigation();
  updateToolbar(tool);
  delete app.dataset.workflowText;
  app.innerHTML = '<section class="card"><p>Loading tool…</p></section>';
  try {
    const renderer = await tool.load();
    if (version !== activationVersion) return;
    setActiveToolScope(app);
    renderer(app);
    initializeToolDragging(tool);
    app.querySelectorAll('[data-open-tool]').forEach(button => { button.onclick = () => { setCanvasMode(false); activate(button.dataset.openTool); }; });
    updateActiveNavigation();
    if (recordRecent && tool.id !== 'dashboard') {
      recentTools = [tool.id, ...recentTools.filter(x => x !== tool.id)].slice(0, 10);
      renderNavigation();
      updateActiveNavigation();
    }
  } catch (error) {
    if (version !== activationVersion) return;
    app.innerHTML = `<section class="card"><h2>Unable to load ${escapeHtml(tool.name)}</h2><div class="status danger">${escapeHtml(error.message || 'Tool module failed to load.')}</div><p class="small">Check the browser console and confirm the module file is published at the expected GitHub Pages path.</p></section>`;
  }
}

function loadExample() {
  const tool = TOOL_BY_ID.get(currentToolId);
  if (!tool?.example) return;
  try {
    for (const field of tool.example.values || []) {
      const input = app.querySelector(field.selector);
      if (!input) throw new Error(`Example target ${field.selector} was not found in this tool.`);
      input.value = field.value;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (tool.example.runSelector) {
      const run = app.querySelector(tool.example.runSelector);
      if (!run) throw new Error(`Example action ${tool.example.runSelector} was not found.`);
      run.click();
    }
    showToolMessage('Example loaded. Review or edit the sample before using it.', 'success');
  } catch (error) { showToolMessage(error.message, 'error'); }
}
document.querySelector('#loadToolExample').addEventListener('click', loadExample);

document.querySelector('#addToWorkflow').addEventListener('click', () => {
  const tool = TOOL_BY_ID.get(currentToolId);
  if (!tool?.workflowSource) return;
  const value = app.dataset.workflowText || app.querySelector(tool.workflowSource)?.value || '';
  try {
    const item = addWorkflowArtifact({ name: `${tool.name} input`, source: tool.name, content: value, contentType: 'text/plain' });
    showToolMessage(`Added “${item.name}” to workflow (${formatBytes(item.bytes)}).`, 'success');
  } catch (error) { showToolMessage(error.message, 'error'); }
});
document.querySelector('#openInCanvas').addEventListener('click', async () => {
  setCanvasMode(true);
  await addToolToCanvas(currentToolId);
});

function renderWorkflowItems() {
  const target = document.querySelector('#workflowItems');
  const items = listWorkflowArtifacts();
  document.querySelector('#workflowCount').textContent = String(items.length);
  if (!items.length) {
    target.innerHTML = '<p class="small">No workflow artifacts yet. Add text from a supported tool to pass it to another tool.</p>';
    return;
  }
  const destinations = TOOL_REGISTRY.filter(tool => tool.workflowTarget);
  target.innerHTML = items.map(item => `<div class="workflow-item" data-artifact-id="${escapeHtml(item.id)}">
    <div><strong>${escapeHtml(item.name)}</strong><span class="small">${escapeHtml(item.source)} · ${formatBytes(item.bytes)}</span></div>
    <select aria-label="Open ${escapeHtml(item.name)} in" data-open-target>${destinations.map(tool => `<option value="${escapeHtml(tool.id)}">${escapeHtml(tool.name)}</option>`).join('')}</select>
    <button class="btn workflow-open" type="button" data-open-artifact="${escapeHtml(item.id)}">Open</button>
    <button class="btn secondary" type="button" data-remove-artifact="${escapeHtml(item.id)}" aria-label="Remove ${escapeHtml(item.name)}">✕</button>
  </div>`).join('');
  target.querySelectorAll('[data-remove-artifact]').forEach(button => button.onclick = () => removeWorkflowArtifact(button.dataset.removeArtifact));
  target.querySelectorAll('[data-open-artifact]').forEach(button => button.onclick = async () => {
    const item = getWorkflowArtifact(button.dataset.openArtifact);
    const row = button.closest('.workflow-item');
    const targetId = row.querySelector('[data-open-target]').value;
    if (item) await openArtifactInTool(item, targetId);
  });
}
window.addEventListener('toolbox:workflow-changed', renderWorkflowItems);

document.querySelector('#workspaceToggle').addEventListener('click', () => workspaceDialog.showModal());
document.querySelector('#closeWorkspace').addEventListener('click', () => workspaceDialog.close());
document.querySelector('#clearWorkflow').addEventListener('click', () => {
  clearWorkflow();
  document.querySelector('#workspaceStatus').textContent = 'Workflow cleared.';
});

async function openArtifactInTool(item, targetId) {
  const tool = TOOL_BY_ID.get(targetId);
  if (!tool?.workflowTarget) return;
  let root = app;
  if (canvasMode) {
    const entry = await addToolToCanvas(targetId);
    if (!entry) return;
    root = entry.root;
  } else {
    await activate(targetId, true, true);
  }
  setActiveToolScope(root);
  const target = root.querySelector(tool.workflowTarget.selector);
  if (!target) {
    document.querySelector('#workspaceStatus').textContent = `The ${tool.name} import target was not available.`;
    return;
  }
  target.value = item.content;
  target.dispatchEvent(new Event('input', { bubbles: true }));
  target.dispatchEvent(new Event('change', { bubbles: true }));
  if (tool.workflowTarget.runSelector) {
    const run = root.querySelector(tool.workflowTarget.runSelector);
    if (run) run.click();
  }
  workspaceDialog.close();
  if (canvasMode) {
    const entry = canvasPanels.get(tool.id);
    if (entry) focusCanvasPanel(entry.panel);
  } else {
    showToolMessage(`Loaded “${item.name}” from workflow.`, 'success');
  }
}

function getCanvasPanelLayouts() {
  return [...canvasPanels.entries()].map(([id, entry]) => {
    const { panel, tool } = entry;
    const maximized = panel.classList.contains('is-maximized');
    let left = Number.parseFloat(panel.style.left) || 0;
    let top = Number.parseFloat(panel.style.top) || 0;
    let width = Number.parseFloat(panel.style.width) || panel.offsetWidth || 640;
    let height = panel.classList.contains('is-minimized')
      ? Number.parseFloat(panel.dataset.expandedHeight) || 520
      : Number.parseFloat(panel.style.height) || panel.offsetHeight || 520;
    let minimized = panel.classList.contains('is-minimized');

    // A maximized panel's visible rectangle is the viewport, not its saved
    // desktop placement. Export its restore rectangle so another screen can
    // recreate the arrangement faithfully.
    if (maximized) {
      try {
        const previous = JSON.parse(panel.dataset.previousRect || '{}');
        left = Number.parseFloat(previous.left) || left;
        top = Number.parseFloat(previous.top) || top;
        width = Number.parseFloat(previous.width) || width;
        height = Number.parseFloat(previous.height) || height;
        minimized = previous.minimized === 'true';
      } catch { /* keep the visible rectangle as a safe fallback */ }
    }

    return {
      id,
      name: tool.name,
      category: tool.category,
      left,
      top,
      width,
      height,
      minimized,
      maximized,
      zIndex: Number.parseInt(panel.style.zIndex, 10) || 0
    };
  });
}

function makeWorkspace() {
  return {
    application: 'Admin Toolbox',
    format: 'admin-toolbox-workspace',
    version: 1,
    exportedAt: new Date().toISOString(),
    activeTool: currentToolId,
    theme: document.documentElement.dataset.theme === 'modern' ? 'modern' : 'classic',
    favorites: [...favorites],
    recentTools,
    canvas: getCanvasPanelLayouts(),
    artifacts: listWorkflowArtifacts().map(({ name, source, contentType, content, addedAt }) => ({ name, source, contentType, content, addedAt }))
  };
}
document.querySelector('#exportWorkspace').addEventListener('click', () => {
  const status = document.querySelector('#workspaceStatus');
  try {
    const json = JSON.stringify(makeWorkspace(), null, 2);
    const bytes = new TextEncoder().encode(json).byteLength;
    if (bytes > MAX_WORKSPACE_FILE_BYTES) throw new Error('Workspace export exceeds 64 MiB. Remove some workflow items and try again.');
    downloadText('admin-toolbox-workspace.json', json, 'application/json;charset=utf-8');
    status.textContent = 'Workspace exported. Keep the file secure; it may contain sensitive log or configuration text.';
  } catch (error) { status.textContent = error.message || 'Unable to export workspace.'; }
});
document.querySelector('#exportCanvas').addEventListener('click', () => {
  const status = document.querySelector('#canvasLayoutStatus');
  try {
    if (!canvasPanels.size) throw new Error('Add at least one tool before exporting the Canvas.');
    const canvasFile = createCanvasLayoutExport(getCanvasPanelLayouts());
    const json = JSON.stringify(canvasFile, null, 2);
    downloadText('admin-toolbox-canvas.json', json, 'application/json;charset=utf-8');
    status.textContent = 'Canvas layout exported. Only tool selections and panel positions/sizes were included.';
  } catch (error) {
    status.textContent = error.message || 'Unable to export Canvas.';
  }
});

document.querySelector('#importCanvas').addEventListener('click', () => document.querySelector('#canvasLayoutFile').click());
document.querySelector('#canvasLayoutFile').addEventListener('change', async event => {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  const status = document.querySelector('#canvasLayoutStatus');
  try {
    if (file.size > 256 * 1024) throw new Error('Canvas layout file exceeds the 256 KiB import limit.');
    const canvasToolIds = new Set(TOOL_REGISTRY.filter(tool => tool.id !== 'dashboard').map(tool => tool.id));
    const parsed = parseCanvasLayoutExport(JSON.parse(await file.text()), canvasToolIds, MAX_CANVAS_PANELS);
    for (const entry of canvasPanels.values()) {
      document.dispatchEvent(new CustomEvent('toolbox:tool-deactivate', { detail: { toolId: entry.tool.id, scope: entry.root } }));
    }
    canvasPanels.clear();
    canvasBoard.replaceChildren();
    canvasBoard.style.minHeight = '';
    setCanvasMode(true);
    document.querySelector('#canvasHint').hidden = true;
    for (const layout of parsed.panels) await addToolToCanvas(layout.id, layout);
    status.textContent = `Canvas imported from ${file.name}. Tool inputs were not imported.`;
  } catch (error) {
    status.textContent = error.message || 'Unable to import Canvas.';
  }
});

document.querySelector('#importWorkspace').addEventListener('click', () => document.querySelector('#workspaceFile').click());
document.querySelector('#workspaceFile').addEventListener('change', async event => {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  const status = document.querySelector('#workspaceStatus');
  try {
    if (file.size > MAX_WORKSPACE_FILE_BYTES) throw new Error('Workspace file exceeds the 64 MiB import limit.');
    const workspace = JSON.parse(await file.text());
    if (!workspace || workspace.application !== 'Admin Toolbox' || workspace.format !== 'admin-toolbox-workspace' || workspace.version !== 1) throw new Error('Unsupported workspace file or version.');
    if (!Array.isArray(workspace.favorites) || !Array.isArray(workspace.recentTools) || !Array.isArray(workspace.artifacts)) throw new Error('Workspace structure is incomplete.');
    if (workspace.canvas !== undefined && (!Array.isArray(workspace.canvas) || workspace.canvas.length > MAX_CANVAS_PANELS)) throw new Error('Workspace Canvas layout is invalid or exceeds the open-panel limit.');
    const validId = id => typeof id === 'string' && TOOL_BY_ID.has(id);
    const canvasLayouts = (workspace.canvas || []).filter(item => item && validId(item.id)).slice(0, MAX_CANVAS_PANELS);
    if (new Set(canvasLayouts.map(item => item.id)).size !== canvasLayouts.length) throw new Error('Workspace Canvas contains duplicate tools.');
    // Validate and replace artifacts before mutating the other workspace state.
    replaceWorkflowArtifacts(workspace.artifacts);
    favorites.clear();
    workspace.favorites.filter(validId).forEach(id => favorites.add(id));
    recentTools = [...new Set(workspace.recentTools.filter(validId))].slice(0, 10);
    if (workspace.theme === 'classic' || workspace.theme === 'modern') {
      document.documentElement.dataset.theme = workspace.theme;
      document.querySelector('#themeToggle')?.setAttribute('aria-pressed', String(workspace.theme === 'modern'));
    }
    renderNavigation();
    renderWorkflowItems();
    const active = validId(workspace.activeTool) ? workspace.activeTool : 'dashboard';
    await activate(active, true, false);
    for (const entry of canvasPanels.values()) {
      document.dispatchEvent(new CustomEvent('toolbox:tool-deactivate', { detail: { toolId: entry.tool.id, scope: entry.root } }));
    }
    canvasPanels.clear();
    canvasBoard.replaceChildren();
    if (canvasLayouts.length) {
      setCanvasMode(true);
      for (const layout of canvasLayouts) await addToolToCanvas(layout.id, layout);
    } else {
      setCanvasMode(false);
    }
    status.textContent = `Workspace imported from ${file.name}.`;
  } catch (error) { status.textContent = error.message || 'Unable to import workspace.'; }
});

renderNavigation();
renderWorkflowItems();
const initialTool = location.hash.slice(1) || 'dashboard';
activate(initialTool, false, true);
window.addEventListener('popstate', () => activate(location.hash.slice(1) || 'dashboard', false, false));
