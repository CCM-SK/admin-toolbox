import { TOOL_REGISTRY } from '../registry.js';

export function renderAudit(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Audit / architecture</h2>
      <p class="small">
        Use this screen when reviewing the deployment model.
      </p>
      <div class="grid">
        <div class="stat">
          <span>Frontend</span>
          <strong>Static HTML/CSS/ES modules</strong>
        </div>
        <div class="stat">
          <span>Processing</span>
          <strong>Browser memory</strong>
        </div>
        <div class="stat">
          <span>Application network calls</span>
          <strong>None</strong>
        </div>
        <div class="stat">
          <span>Application persistence</span>
          <strong>None</strong>
        </div>
      </div>
      <h3>Controls</h3>
      <ul>
        <li>CSP includes <span class="mono">connect-src 'none'</span>.</li>
        <li>No third-party runtime/CDN dependencies.</li>
        <li>No analytics, cookies, localStorage, sessionStorage or IndexedDB. Favorites, recents and workflow items exist only in the current tab session.</li>
        <li>Files enter through explicit user file selection or drag-and-drop.</li>
        <li>Cryptographic randomness uses Web Crypto.</li>
        <li>Exports happen only after explicit user action. Workspace export may include user-selected workflow text.</li>
        <li>Tools are loaded on demand with same-origin ES module imports.</li>
        <li>Every tool page has a draggable title bar when the sidebar is detached; drag the title bar to reposition the active tool.</li>
        <li>The sidebar can be collapsed and is automatically tucked away when entering Work Canvas.</li>
        <li>Work Canvas tools are grouped by category and sorted by tool name. Canvas-only export/import stores panel layout metadata, not tool input or workflow content.</li>
        <li>Large log files are scanned by a same-origin Web Worker using streaming file reads.</li>
      </ul>
      <h3>Audit manifest</h3>
      <pre id="manifest" class="mono"></pre>
      <a
        class="btn"
        href="audit-manifest.json"
        download="audit-manifest.json"
      >Download audit manifest</a>
    </section>
  `;
  const manifest = {
    application: 'Admin Toolbox',
    version: '0.1.8.0-beta',
    architecture: 'GitHub Pages -> static HTML/CSS/ES modules -> browser -> local processing -> result/download',
    loading: { toolModules: 'on-demand same-origin dynamic imports', buildStepRequired: false },
    network: { connectSrc: "'none'", externalRequests: false, thirdPartyRuntimeRequests: false },
    storage: {
      localStorage: false, sessionStorage: false, indexedDB: false,
      applicationCookies: false,
      sessionMemory: ['favorites', 'recent tools', 'workflow artifacts', 'Work Canvas panels and layout']
    },
    workers: [{ id: 'log-worker', purpose: 'streaming search and filtering for large log files', source: 'js/workers/log-worker.js' }],
    dependencies: { thirdPartyRuntime: false, cdn: false },
    fileInput: { userSelection: true, dragAndDrop: true },
    exports: { userInitiatedOnly: true, workspaceIncludesWorkflowText: true, canvasLayoutExportIncludesToolInputs: false, canvasLayoutExportIncludesWorkflowText: false },
    tools: TOOL_REGISTRY.filter(tool => tool.id !== 'dashboard').map(tool => ({
      id: tool.id, name: tool.name, category: tool.category, description: tool.description
    })),
    features: ['global tool search', 'session favorites and recents', 'sample inputs', 'in-memory workflows', 'workspace JSON import/export', 'large-file log scanning', 'multi-tool Work Canvas', 'collapsible sidebar', 'standalone Canvas layout export/import', 'category-grouped and alphabetized Canvas tool picker', 'draggable tool windows when sidebar is detached'],
    review: { auditScreen: true, securityDoc: 'SECURITY.md' },
    limitations: [
      'Certificate inspector is a conservative ASN.1 string inspector, not a PKI validator.',
      'Configuration diff is line-oriented rather than semantic.',
      'Large-file mode in Log Inspector is line-oriented (250 MiB file limit), skips lines over 1 MiB of UTF-8 text, previews at most 1,000 lines / 4 MiB, and caps filtered exports at 24 MiB; CSV column analysis is limited to normal mode.',
      'Workspace files may contain sensitive text explicitly added to the workflow. Protect exported files.',
      'Canvas-only files contain tool identifiers and panel geometry but not tool inputs or workflow text.'
    ]
  };
  app.querySelector('#manifest').textContent = JSON.stringify(manifest, null, 2);
}
