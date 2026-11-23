const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 24 * 1024 * 1024;
const MAX_ARTIFACTS = 30;
let artifacts = [];
let nextId = 1;

function bytesOf(text) { return new TextEncoder().encode(text).byteLength; }

export function listWorkflowArtifacts() { return artifacts.map(item => ({ ...item })); }
export function getWorkflowArtifact(id) { return artifacts.find(item => item.id === id) || null; }
export function clearWorkflow() { artifacts = []; nextId = 1; notify(); }
export function removeWorkflowArtifact(id) { artifacts = artifacts.filter(item => item.id !== id); notify(); }
export function addWorkflowArtifact({ name, source, content, contentType = 'text/plain' }) {
  if (typeof content !== 'string' || !content.trim()) throw new Error('There is no text content to add.');
  const size = bytesOf(content);
  if (size > MAX_ARTIFACT_BYTES) throw new Error('Each workflow item is limited to 8 MiB.');
  if (artifacts.length >= MAX_ARTIFACTS) throw new Error(`A workspace can contain at most ${MAX_ARTIFACTS} workflow items.`);
  const used = artifacts.reduce((sum, item) => sum + item.bytes, 0);
  if (used + size > MAX_TOTAL_BYTES) throw new Error('The workflow queue is limited to 24 MiB in total. Remove an item before adding more.');
  const item = {
    id: `artifact-${nextId++}`,
    name: String(name || `Artifact ${artifacts.length + 1}`).slice(0, 120),
    source: String(source || 'Unknown tool').slice(0, 80),
    contentType: String(contentType || 'text/plain').slice(0, 80),
    content,
    bytes: size,
    addedAt: new Date().toISOString()
  };
  artifacts.push(item);
  notify();
  return item;
}
export function replaceWorkflowArtifacts(items) {
  if (!Array.isArray(items) || items.length > MAX_ARTIFACTS) throw new Error('Invalid workflow item list.');
  let total = 0;
  const normalized = items.map((item, index) => {
    if (!item || typeof item.content !== 'string' || typeof item.name !== 'string') throw new Error('A workflow item is malformed.');
    const bytes = bytesOf(item.content);
    if (bytes > MAX_ARTIFACT_BYTES) throw new Error(`Workflow item ${index + 1} exceeds 8 MiB.`);
    total += bytes;
    if (total > MAX_TOTAL_BYTES) throw new Error('The imported workflow exceeds 24 MiB.');
    return {
      id: `artifact-${index + 1}`,
      name: item.name.slice(0, 120),
      source: String(item.source || 'Imported').slice(0, 80),
      contentType: String(item.contentType || 'text/plain').slice(0, 80),
      content: item.content,
      bytes,
      addedAt: typeof item.addedAt === 'string' ? item.addedAt : new Date().toISOString()
    };
  });
  artifacts = normalized;
  nextId = normalized.length + 1;
  notify();
}
function notify() {
  window.dispatchEvent(new CustomEvent('toolbox:workflow-changed', { detail: { count: artifacts.length } }));
}
