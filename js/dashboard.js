import { escapeHtml } from './utils.js';

export function renderDashboard(app) {
  app.innerHTML = `
    <section class="card hero">
      <h2>Local-only Admin Toolbox</h2>
      <p>
        Six practical utilities for administrative IT work.
        Everything you give the app is processed inside this browser tab.
      </p>

      <div class="status ok">
        <strong>Network policy:</strong>
        this build uses no <span class="mono">fetch()</span>, WebSocket,
        third-party script, CDN, analytics or API endpoint.
        The CSP also sets <span class="mono">connect-src 'none'</span>.
      </div>
    </section>

    <section class="grid">
      <article class="card">
        <h3>1 · Log / CSV inspector</h3>
        <p>
          Load CSV or plain text logs, search them, count values,
          and export filtered data.
        </p>
      </article>

      <article class="card">
        <h3>2 · File hashing</h3>
        <p>
          Calculate MD5, SHA-1 and SHA-256 hashes locally using
          browser APIs plus a bundled pure-JS MD5 implementation.
        </p>
      </article>

      <article class="card">
        <h3>3 · IP / subnet calculator</h3>
        <p>
          IPv4 and IPv6 CIDR calculations, ranges, masks and host counts.
        </p>
      </article>

      <article class="card">
        <h3>4 · Certificate / CSR inspector</h3>
        <p>
          Inspect PEM certificates and CSRs locally by decoding
          common ASN.1 string fields.
        </p>
      </article>

      <article class="card">
        <h3>5 · Password generator</h3>
        <p>
          Generate passwords and passphrases with browser cryptographic
          randomness. Nothing is stored.
        </p>
      </article>

      <article class="card">
        <h3>6 · Configuration diff</h3>
        <p>
          Compare two local text/config files with a simple line-oriented diff.
        </p>
      </article>
    </section>

      <article class="card">
        <h3>7 · Powershell Analyzer</h3>
        <p>
          Flags code.
        </p>
      </article>
    </section>

      <article class="card">
        <h3>8 · SID/GUID Decoder</h3>
        <p>
          Parsing of several SIDs and GUIDs
        </p>
      </article>
    </section>

     <article class="card">
        <h3>9 · Regex Workbench</h3>
        <p>
          Regex Engine, flagging, preview and export
        </p>
      </article>
    </section>

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
