import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanvasLayoutExport, displaySpaceName, parseCanvasLayoutExport, resolveCanvasPanelDimensions, sortToolsBySpaceThenName } from '../js/canvas-layout.js';

const tools = [
  { id: 'z', category: 'Security & identity', name: 'Zulu' },
  { id: 'b', category: 'Diagnostics', name: 'Beta' },
  { id: 'a', category: 'Diagnostics', name: 'Alpha' },
  { id: 'n', category: 'Network & firewall', name: 'Analyzer' }
];

test('Canvas tool picker sorting is by space, then tool name', () => {
  const sorted = sortToolsBySpaceThenName(tools);
  assert.deepEqual(sorted.map(tool => tool.id), ['a', 'b', 'n', 'z']);
  assert.equal(displaySpaceName('Security & identity'), 'Security & Identity');
});

test('Canvas export contains panel selections and geometry only', () => {
  const layout = createCanvasLayoutExport([
    { id: 'b', name: 'Beta', category: 'Diagnostics', left: 420, top: 90, width: 720, height: 560, minimized: false, maximized: false, zIndex: 4, input: 'sensitive text' },
    { id: 'a', name: 'Alpha', category: 'Diagnostics', left: 20, top: 30, width: 500, height: 420, minimized: true, maximized: false, zIndex: 2, workflowText: 'secret' }
  ], '2026-11-23T16:00:00.000Z');

  assert.equal(layout.format, 'admin-toolbox-canvas');
  assert.deepEqual(layout.panels.map(panel => panel.id), ['a', 'b']);
  assert.equal(layout.panels[1].left, 420);
  assert.equal(layout.panels[1].width, 720);
  assert.equal(layout.panels[1].height, 560);
  assert.equal(layout.panels[0].minimized, true);
  assert.doesNotMatch(JSON.stringify(layout), /sensitive text|secret|workflowText|input/);
});

test('Canvas layout import validates known tools, duplicates and geometry', () => {
  const known = new Set(['a', 'b']);
  const base = {
    application: 'Admin Toolbox', format: 'admin-toolbox-canvas', version: 1,
    panels: [{ id: 'a', left: 10, top: 20, width: 500, height: 450, minimized: false, maximized: true, zIndex: 9 }]
  };
  const parsed = parseCanvasLayoutExport(base, known, 16);
  assert.equal(parsed.panels[0].id, 'a');
  assert.equal(parsed.panels[0].maximized, true);
  assert.throws(() => parseCanvasLayoutExport({ ...base, panels: [...base.panels, ...base.panels] }, known), /duplicate/);
  assert.throws(() => parseCanvasLayoutExport({ ...base, panels: [{ ...base.panels[0], id: 'unknown' }] }, known), /unknown/);
  assert.throws(() => parseCanvasLayoutExport({ ...base, panels: [{ ...base.panels[0], left: -1 }] }, known), /left/);
  assert.throws(() => parseCanvasLayoutExport({ ...base, panels: Array(17).fill(base.panels[0]) }, known), /between 1 and 16/);
});


test('Canvas import preserves window dimensions independently of the current viewport', () => {
  const imported = resolveCanvasPanelDimensions({ width: 1680, height: 940 }, { width: 640, height: 520 });
  assert.deepEqual(imported, { width: 1680, height: 940 });

  // Missing or malformed dimensions fall back safely; values remain bounded.
  assert.deepEqual(resolveCanvasPanelDimensions({ width: 'invalid', height: null }, { width: 640, height: 520 }), { width: 640, height: 520 });
  assert.deepEqual(resolveCanvasPanelDimensions({ width: 20000, height: 100 }, { width: 640, height: 520 }), { width: 12000, height: 280 });
});
