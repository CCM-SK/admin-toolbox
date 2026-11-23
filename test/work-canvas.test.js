import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TOOL_REGISTRY } from '../js/registry.js';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('Work Canvas has a header entry point, tool picker and independent panel board', async () => {
  const html = await read('index.html');
  const app = await read('js/app.js');
  assert.match(html, /id="workCanvasToggle"/);
  assert.match(html, /id="workCanvasView" hidden/);
  assert.match(html, /id="canvasToolPicker"/);
  assert.match(html, /id="canvasAddTool"/);
  assert.match(html, /id="workCanvasBoard"/);
  assert.match(html, /id="openInCanvas"/);
  assert.match(app, /async function addToolToCanvas\(id, layout = null\)/);
  assert.match(app, /resolveCanvasPanelDimensions\(layout, \{ width: panelWidth, height: 520 \}\)/);
  assert.match(app, /panel\.style\.width = `\$\{dimensions\.width\}px`/);
  assert.match(app, /panel\.style\.height = `\$\{dimensions\.height\}px`/);
  assert.doesNotMatch(app, /Math\.min\(availableWidth, requestedWidth\)/);
  assert.match(app, /const MAX_CANVAS_PANELS = 16/);
  assert.match(app, /canvasPanels\.get\(tool\.id\)/);
});

test('Canvas panels support move, resize, minimize, maximize and close operations', async () => {
  const app = await read('js/app.js');
  const css = await read('css/app.css');
  for (const selector of ['[data-canvas-minimize]', '[data-canvas-maximize]', '[data-canvas-close]', '.canvas-panel-resize']) {
    assert.ok(app.includes(selector), `missing canvas control ${selector}`);
  }
  assert.match(app, /header\.addEventListener\('pointermove'/);
  assert.match(app, /resizeHandle\.addEventListener\('pointermove'/);
  assert.match(app, /panel\.style\.left =/);
  assert.match(app, /panel\.style\.width =/);
  assert.match(css, /\.canvas-panel\.is-minimized/);
  assert.match(css, /\.canvas-panel\.is-maximized/);
  assert.match(css, /@media \(max-width: 900px\)[\s\S]*?\.canvas-panel \{/);
});

test('tool selectors are scoped to the canvas panel in use', async () => {
  const utils = await read('js/utils.js');
  const app = await read('js/app.js');
  assert.match(utils, /export function setActiveToolScope\(root\)/);
  assert.match(utils, /root = activeToolScope \|\| document/);
  assert.match(app, /canvasBoard\.addEventListener\('pointerdown'/);
  assert.match(app, /canvasBoard\.addEventListener\('focusin'/);

  // Multiple active tools reuse a handful of IDs. Their modules must not use
  // document-global selectors, which would accidentally target another panel.
  const globalSelector = /document\.(?:querySelector|querySelectorAll|getElementById)\s*\(/;
  for (const tool of TOOL_REGISTRY) {
    const source = await read(`js/${tool.modulePath.replace(/^\.\//, '')}`);
    assert.doesNotMatch(source, globalSelector, `${tool.id} still uses a document-global selector`);
  }
});

test('Canvas layout is included in workspace export/import but tool inputs are not implicitly exported', async () => {
  const app = await read('js/app.js');
  const readme = await read('README.md');
  assert.match(app, /canvas: getCanvasPanelLayouts\(\)/);
  assert.match(app, /workspace\.canvas !== undefined/);
  assert.match(app, /await addToolToCanvas\(layout\.id, layout\)/);
  assert.match(readme, /Work Canvas panel layout/);
  assert.match(readme, /Panel input fields are not exported automatically/);
});

test('closing a Canvas tool only deactivates the matching tool instance', async () => {
  const app = await read('js/app.js');
  const logs = await read('js/tools/logs.js');
  assert.match(app, /toolId: tool\.id, scope: root/);
  assert.match(logs, /event\.detail\?\.scope && event\.detail\.scope !== app/);
});


test('Canvas sidebar collapses automatically and can be toggled back', async () => {
  const html = await read('index.html');
  const app = await read('js/app.js');
  const css = await read('css/app.css');
  assert.match(html, /id="sidebarToggle"/);
  assert.match(app, /function setSidebarCollapsed\(collapsed\)/);
  assert.match(app, /sidebarCollapsedBeforeCanvas = document\.body\.classList\.contains\('sidebar-collapsed'\)/);
  assert.match(app, /setSidebarCollapsed\(true\)/);
  assert.match(app, /setSidebarCollapsed\(sidebarCollapsedBeforeCanvas\)/);
  assert.match(css, /body\.sidebar-collapsed \.sidebar\s*\{\s*display: none !important/);
});

test('Canvas controls expose a dedicated layout export and import without tool inputs', async () => {
  const html = await read('index.html');
  const app = await read('js/app.js');
  const layout = await read('js/canvas-layout.js');
  assert.match(html, /id="exportCanvas"[^>]*>Export Canvas/);
  assert.match(html, /id="importCanvas"[^>]*>Import Canvas/);
  assert.match(app, /createCanvasLayoutExport\(getCanvasPanelLayouts\(\)\)/);
  assert.match(app, /parseCanvasLayoutExport\(JSON\.parse\(await file\.text\(\)\)/);
  assert.match(layout, /format: 'admin-toolbox-canvas'/);
  assert.doesNotMatch(layout, /artifacts|inputValue|workflowText/i);
});
