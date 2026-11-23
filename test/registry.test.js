import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { TOOL_REGISTRY, TOOL_BY_ID } from '../js/registry.js';

test('tool registry has unique IDs and required metadata', () => {
  const ids = TOOL_REGISTRY.map(tool => tool.id);
  assert.equal(new Set(ids).size, ids.length, 'tool IDs must be unique');
  for (const tool of TOOL_REGISTRY) {
    assert.ok(tool.name, `${tool.id} needs a name`);
    assert.ok(tool.category, `${tool.id} needs a category`);
    assert.ok(tool.description, `${tool.id} needs a description`);
    assert.equal(typeof tool.load, 'function', `${tool.id} needs a lazy loader`);
  }
});

test('workflow targets and example selectors are declared', () => {
  for (const tool of TOOL_REGISTRY) {
    if (tool.workflowTarget) {
      assert.ok(tool.workflowTarget.selector, `${tool.id} workflow target needs a selector`);
    }
    for (const field of tool.example?.values || []) {
      assert.ok(field.selector && typeof field.value === 'string', `${tool.id} has an invalid example field`);
    }
  }
});

test('static audit manifest is generated from the registry', async () => {
  const manifest = JSON.parse(await readFile(new URL('../audit-manifest.json', import.meta.url), 'utf8'));
  const expected = TOOL_REGISTRY.filter(tool => tool.id !== 'dashboard').map(tool => tool.id).sort();
  const actual = manifest.tools.map(tool => tool.id).sort();
  assert.deepEqual(actual, expected);
});

test('all declared workflow targets point to their tool controls', async () => {
  for (const tool of TOOL_REGISTRY.filter(item => item.workflowTarget)) {
    assert.ok(TOOL_BY_ID.has(tool.id));
    const source = await readFile(new URL(tool.modulePath, new URL('../js/registry.js', import.meta.url)), 'utf8');
    const selectors = [tool.workflowTarget.selector, tool.workflowTarget.runSelector].filter(Boolean);
    for (const selector of selectors) {
      assert.match(selector, /^#[A-Za-z][\w-]*$/);
      assert.ok(source.includes(selector.slice(1)), `${tool.id} workflow selector ${selector} is missing from ${tool.modulePath}`);
    }
  }
});

test('every registry lazy loader resolves to a renderer', async () => {
  for (const tool of TOOL_REGISTRY) {
    const renderer = await tool.load();
    assert.equal(typeof renderer, 'function', `${tool.id} renderer should be a function`);
  }
});

test('every declared sample points to selectors in its tool source', async () => {
  for (const tool of TOOL_REGISTRY.filter(item => item.example)) {
    const sourceUrl = new URL(tool.modulePath, new URL('../js/registry.js', import.meta.url));
    const source = await readFile(sourceUrl, 'utf8');
    const selectors = [
      ...(tool.example.values || []).map(field => field.selector),
      ...(tool.example.runSelector ? [tool.example.runSelector] : [])
    ];
    for (const selector of selectors) {
      assert.match(selector, /^#[A-Za-z][\w-]*$/, `${tool.id} has an unsupported sample selector: ${selector}`);
      assert.ok(source.includes(selector.slice(1)), `${tool.id} sample selector ${selector} is missing from ${tool.modulePath}`);
    }
  }
});

test('strict CSP is supported by the static templates (no inline style attributes)', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /style-src-attr 'none'/);
  assert.doesNotMatch(html, /\sstyle\s*=/i);
});

test('the registry manifest documents the implemented client-side features', async () => {
  const manifest = JSON.parse(await readFile(new URL('../audit-manifest.json', import.meta.url), 'utf8'));
  for (const feature of ['global tool search', 'session favorites and recents', 'sample inputs', 'in-memory workflows', 'workspace JSON import/export', 'large-file log scanning', 'draggable tool windows when sidebar is detached']) {
    assert.ok(manifest.features.includes(feature), `manifest is missing ${feature}`);
  }
  assert.ok(manifest.workers.some(worker => worker.source === 'js/workers/log-worker.js'));
});
