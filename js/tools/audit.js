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
        <li>No analytics, cookies, localStorage, sessionStorage or IndexedDB.</li>
        <li>Files enter through explicit user file selection or drag-and-drop.</li>
        <li>Cryptographic randomness uses Web Crypto.</li>
        <li>Exports happen only after explicit user action.</li>
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
    architecture:
      'GitHub Pages -> static HTML/CSS/JS -> browser -> local processing -> result/download',
    network: {
      connectSrc: "'none'",
      externalRequests: false,
      thirdPartyRuntimeRequests: false
    },
    storage: {
      localStorage: false,
      sessionStorage: false,
      indexedDB: false,
      applicationCookies: false
    },
    dependencies: {
      thirdPartyRuntime: false,
      cdn: false
    },
    fileInput: {
      userSelection: true,
      dragAndDrop: true
    },
    exports: {
      userInitiatedOnly: true
    },
    tools: [
      'archive-metadata',
      'event-viewer',
      'url-analyzer',
      'encoding-decoding',
      'powershell-analyzer',
      'regex-workbench',
      'ssh-key-inspector',
      'vlan-planner',
      'password-generator',
      'configuration-diff',
      'certificate-inspector',
      'file-hashing',
      'ip-subnet-calculator',
      'log-csv-inspector',
      'secret-detector',
      'ssh-share',
      'driver-inspector',
      'identity-inspector',
      'header-analyzer',
      'json-yaml-xml-workbench',
      'identity-metadata'
    ],
    review: {
      auditScreen: true,
      securityDoc: 'SECURITY.md'
    },
    limitations: [
      'Certificate inspector is a conservative ASN.1 string inspector, not a PKI validator.',
      'Diff is line-oriented rather than semantic.',
      'Files loaded into browser memory.'
    ]
  };

  $('#manifest').textContent = JSON.stringify(manifest, null, 2);
}
