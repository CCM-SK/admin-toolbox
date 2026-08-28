import { escapeHtml } from './utils.js';

const tools = import.meta.glob('./tools/*.js', {
  eager: true,
  import: 'metadata'
});

export function renderDashboard(app) {

  const cards = Object.values(tools)
    .filter(Boolean)
    .map(tool => `
      <a class="card" href="#${escapeHtml(tool.metadata.path)}">
        <h3>${escapeHtml(tool.metadata.title)}</h3>
        <p>${escapeHtml(tool.metadata.description)}</p>
      </a>
    `)
    .join('');

  app.innerHTML = `
    <section class="card hero">
      <h2>Local-only Admin Toolbox</h2>
      <p>
        Practical utilities for administrative IT work.
        Everything you give the app is processed inside this browser tab.
      </p>

      <div class="status ok">
        <strong>Network policy:</strong>
        this build uses no <span class="mono">fetch()</span>, WebSocket,
        third-party script, CDN, analytics or API endpoint.
        The CSP also sets <span class="mono">connect-src 'none'</span>.
      </div>
    </section>

    ${/* <section class="grid">
      <article class="card">
        <h3>Log / CSV inspector</h3>
        <p>
          Load CSV or plain text logs, search them, count values,
          and export filtered data.
        </p>
      </article>

      <article class="card">
        <h3>File hashing</h3>
        <p>
          Calculate MD5, SHA-1 and SHA-256 hashes locally using
          browser APIs plus a bundled pure-JS MD5 implementation.
        </p>
      </article>

      <article class="card">
        <h3>IP / subnet calculator</h3>
        <p>
          IPv4 and IPv6 CIDR calculations, ranges, masks and host counts.
        </p>
      </article>

      <article class="card">
        <h3>Certificate / CSR inspector</h3>
        <p>
          Inspect PEM certificates and CSRs locally by decoding
          common ASN.1 string fields.
        </p>
      </article>

      <article class="card">
        <h3>Password generator</h3>
        <p>
          Generate passwords and passphrases with browser cryptographic
          randomness. Nothing is stored.
        </p>
      </article>

      <article class="card">
        <h3>Configuration diff</h3>
        <p>
          Compare two local text/config files with a simple line-oriented diff.
        </p>
      </article>

      <article class="card">
        <h3>Powershell Analyzer</h3>
        <p>
          Checks common security, reliability, and readability issues.
        </p>
      </article>

      <article class="card">
        <h3>SID/GUID Decoder</h3>
        <p>
          Parses and recognizes Windows SIDs, GUIDs, UUID byte strings, and common GUID representations.
        </p>
      </article>

     <article class="card">
        <h3>Regex Workbench</h3>
        <p>
          JavaScript regular expressions only, flagging, preview and export.
        </p>
      </article>

      <article class="card">
        <h3>Driver Assistant</h3>
        <p>
          Work in progress
        </p>

      </article>
            <article class="card">
        <h3>Event Viewer Analyzer</h3>
        <p>
          Work in progress
        </p>

      </article>
            <article class="card">
        <h3>Secure Share Password</h3>
        <p>
          Very(!) work in progress
        </p>
      </article>

      <article class="card">
        <h3>Mail-Header analyzer</h3>
        <p>
          Work in progress
        </p>
      </article>
    </section> */ ''}

    <section class="card">
      <h3>Privacy model</h3>
      <p>
        This is deliberately a static application. It does not contain
        a server component. Your files stay in browser memory unless you
        explicitly download a result.
      </p>
      <p class="small">
        Note: the browser still downloads the application itself from
        GitHub Pages. The privacy guarantee applies to the data you process
        after the application has loaded.
      </p>
    </section>
  `;
}
