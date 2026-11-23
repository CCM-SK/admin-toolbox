const activeJobs = new Map();
const MAX_EXPORT_BYTES = 24 * 1024 * 1024;
const MAX_LINE_BYTES = 1024 * 1024;
const MAX_PREVIEW_BYTES = 4 * 1024 * 1024;
const encoder = new TextEncoder();

self.addEventListener('message', event => {
  const message = event.data || {};
  if (message.type === 'cancel') {
    const job = activeJobs.get(message.id);
    if (job) {
      job.cancelled = true;
      job.reader?.cancel().catch(() => {});
    }
    return;
  }
  if (message.type === 'scan' || message.type === 'export') {
    runJob(message).catch(error => self.postMessage({
      type: 'error', id: message.id, message: error?.message || 'Unable to process this file.'
    }));
  }
});

async function runJob(message) {
  const { id, file, query = '', type } = message;
  if (!(file instanceof Blob)) throw new Error('The selected file is not available to the worker.');
  const job = { cancelled: false };
  activeJobs.set(id, job);
  const rawQuery = String(query).slice(0, 500).trim();
  const needle = rawQuery.toLocaleLowerCase();
  let matchesQuery = line => !needle || line.toLocaleLowerCase().includes(needle);
  if (rawQuery.startsWith('/') && rawQuery.lastIndexOf('/') > 0) {
    const lastSlash = rawQuery.lastIndexOf('/');
    try {
      const expression = new RegExp(rawQuery.slice(1, lastSlash), rawQuery.slice(lastSlash + 1));
      matchesQuery = line => { expression.lastIndex = 0; return expression.test(line); };
    } catch { /* Invalid regular expressions fall back to case-insensitive substring matching. */ }
  }
  const reader = file.stream().getReader();
  job.reader = reader;
  const decoder = new TextDecoder();
  let carry = '';
  let droppingLongLine = false;
  let lines = 0;
  let matched = 0;
  let skippedOversizedLines = 0;
  let bytesRead = 0;
  let lastProgress = 0;
  let previewBytes = 0;
  let previewOmitted = 0;
  const preview = [];
  const exportChunks = [];
  let exportBytes = 0;

  const consumeLine = line => {
    lines++;
    const clean = line.endsWith('\r') ? line.slice(0, -1) : line;
    if (!clean) return;
    const lineBytes = encoder.encode(clean).byteLength;
    if (lineBytes > MAX_LINE_BYTES) {
      skippedOversizedLines++;
      return;
    }
    if (!matchesQuery(clean)) return;
    matched++;
    if (preview.length < 1000 && previewBytes + lineBytes <= MAX_PREVIEW_BYTES) {
      preview.push(clean);
      previewBytes += lineBytes;
    } else previewOmitted++;
    if (type === 'export') {
      const chunk = clean + '\n';
      exportBytes += lineBytes + 1;
      if (exportBytes > MAX_EXPORT_BYTES) throw new Error('Filtered export exceeds 24 MiB. Narrow the search before exporting.');
      exportChunks.push(chunk);
    }
  };

  try {
    while (true) {
      if (job.cancelled) return;
      const { value, done } = await reader.read();
      if (done) break;
      bytesRead += value.byteLength;
      let chunk = carry + decoder.decode(value, { stream: true });
      carry = '';
      if (droppingLongLine) {
        const newline = chunk.indexOf('\n');
        if (newline === -1) chunk = '';
        else {
          chunk = chunk.slice(newline + 1);
          droppingLongLine = false;
        }
      }
      const split = chunk.split('\n');
      carry = split.pop() || '';
      for (const line of split) consumeLine(line);
      if (encoder.encode(carry).byteLength > MAX_LINE_BYTES) {
        carry = '';
        droppingLongLine = true;
        lines++;
        skippedOversizedLines++;
      }
      if (bytesRead - lastProgress >= 2 * 1024 * 1024) {
        lastProgress = bytesRead;
        self.postMessage({ type: 'progress', id, bytesRead, fileSize: file.size, lines, matched, skippedOversizedLines });
      }
    }
    if (!droppingLongLine) {
      carry += decoder.decode();
      if (carry) consumeLine(carry);
    }
    if (job.cancelled) return;
    if (type === 'export') {
      const blob = new Blob(exportChunks, { type: 'text/plain;charset=utf-8' });
      self.postMessage({ type: 'exported', id, blob, matched, bytes: blob.size });
    } else {
      self.postMessage({
        type: 'result', id, fileName: file.name, fileSize: file.size, bytesRead,
        lines, matched, skippedOversizedLines, preview, previewOmitted
      });
    }
  } catch (error) {
    if (!job.cancelled) throw error;
  } finally {
    activeJobs.delete(id);
    try { reader.releaseLock(); } catch { /* stream already closed */ }
  }
}
