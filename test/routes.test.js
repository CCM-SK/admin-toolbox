import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAppRoute } from '../js/routes.js';

const known = new Set(['dashboard', 'logs', 'urlanalyzer']);

test('direct #canvas hash opens the Work Canvas route', () => {
  assert.deepEqual(parseAppRoute('#canvas', known), { type: 'canvas' });
  assert.deepEqual(parseAppRoute('#CANVAS', known), { type: 'canvas' });
});

test('known tool hashes remain direct links', () => {
  assert.deepEqual(parseAppRoute('#logs', known), { type: 'tool', id: 'logs' });
});

test('empty and unknown hashes safely fall back to dashboard', () => {
  assert.deepEqual(parseAppRoute('', known), { type: 'tool', id: 'dashboard' });
  assert.deepEqual(parseAppRoute('#missing-tool', known), { type: 'tool', id: 'dashboard' });
});
