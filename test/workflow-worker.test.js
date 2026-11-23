import test from 'node:test';
import assert from 'node:assert/strict';

const workerMessages = [];
const workerListeners = {};
globalThis.self = {
  addEventListener(type, listener) { workerListeners[type] = listener; },
  postMessage(message) { workerMessages.push(message); }
};
await import('../js/workers/log-worker.js');

function sendWorkerMessage(data) {
  workerListeners.message({ data });
}
async function waitForMessage(predicate, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const found = workerMessages.find(predicate);
    if (found) return found;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('Timed out waiting for worker message.');
}

test('large-log worker searches streamed content and skips oversized lines', async () => {
  const blob = new Blob([
    'INFO startup\nERROR database unavailable\n',
    'x'.repeat(1024 * 1024 + 20),
    '\nWARN retry\nERROR connection restored\n'
  ], { type: 'text/plain' });
  Object.defineProperty(blob, 'name', { value: 'worker-test.log' });
  sendWorkerMessage({ type: 'scan', id: 501, file: blob, query: 'error' });
  const result = await waitForMessage(message => message.id === 501 && message.type === 'result');
  assert.equal(result.fileName, 'worker-test.log');
  assert.equal(result.matched, 2);
  assert.equal(result.skippedOversizedLines, 1);
  assert.deepEqual(result.preview, ['ERROR database unavailable', 'ERROR connection restored']);
});

test('large-log worker exports only matching lines within the export cap', async () => {
  const blob = new Blob(['one\nmatch one\ntwo\nmatch two\n']);
  sendWorkerMessage({ type: 'export', id: 502, file: blob, query: 'match' });
  const result = await waitForMessage(message => message.id === 502 && message.type === 'exported');
  assert.equal(result.matched, 2);
  assert.equal(await result.blob.text(), 'match one\nmatch two\n');
});

test('workflow queue enforces per-item and total memory limits', async () => {
  globalThis.window = { dispatchEvent() {} };
  const workflow = await import('../js/workflow.js');
  workflow.clearWorkflow();
  const item = workflow.addWorkflowArtifact({ name: 'Sample', source: 'Unit test', content: 'line one\nline two' });
  assert.equal(workflow.getWorkflowArtifact(item.id).content, 'line one\nline two');
  assert.throws(() => workflow.addWorkflowArtifact({ content: 'x'.repeat(8 * 1024 * 1024 + 1) }), /8 MiB/);
  workflow.clearWorkflow();
});

test('large-log worker cancellation does not report a processing error', async () => {
  let cancelStream;
  const blob = new Blob(['unused']);
  blob.stream = () => new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelStream = true; }
  });
  sendWorkerMessage({ type: 'scan', id: 503, file: blob, query: '' });
  sendWorkerMessage({ type: 'cancel', id: 503 });
  await new Promise(resolve => setTimeout(resolve, 40));
  assert.equal(cancelStream, true);
  assert.equal(workerMessages.some(message => message.id === 503), false);
});

test('large-log worker supports regular-expression searches with flags', async () => {
  const blob = new Blob(['INFO startup\nERROR database unavailable\nwarn retry\nERROR restored\n']);
  sendWorkerMessage({ type: 'scan', id: 504, file: blob, query: '/^error/i' });
  const result = await waitForMessage(message => message.id === 504 && message.type === 'result');
  assert.equal(result.matched, 2);
  assert.deepEqual(result.preview, ['ERROR database unavailable', 'ERROR restored']);
});
