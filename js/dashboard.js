import { TOOL_REGISTRY } from './registry.js';
import { escapeHtml } from './utils.js';

export function renderDashboard(app) {
  const categories = [...new Set(TOOL_REGISTRY.filter(tool => !['Home', 'Administration'].includes(tool.category)).map(tool => tool.category))];
  app.innerHTML = `
    <section class="card hero">
      <h2>Local-only Toolbox</h2>
      <p>Practical utilities for IT administration, troubleshooting, configuration review and security analysis. Files are processed in this browser tab.</p>
      <div class="status ok"><strong>Local processing:</strong> tool modules and workers are static same-origin assets. File contents are not uploaded to an application server.</div>
      <div class="small">Quick search: press <kbd>Ctrl</kbd> + <kbd>K</kbd> or <kbd>/</kbd> to find a tool.</div>
    </section>
    <section class="card">
      <h3>Privacy and workspace model</h3>
      <p>Favorites, recently used tools and workflow artifacts stay in memory for this tab. Use <strong>Workspace → Export workspace</strong> to create a local backup. The backup includes workflow text, so treat it as sensitive.</p>
      <p class="small">The application itself is served by GitHub Pages. The privacy guarantee applies to the data you process after the application has loaded; browser extensions and device-level software remain outside the application's control.</p>
    </section>
    <section class="card">
      <h3>Tool directory</h3>
      <div class="grid-2">${categories.map(category => {
        const tools = TOOL_REGISTRY.filter(tool => tool.category === category);
        return `<article class="card directory-card"><h3>${escapeHtml(category)}</h3><p class="small">${tools.length} tools</p><div class="directory-links">${tools.map(tool => `<button type="button" class="tool-search-result" data-open-tool="${escapeHtml(tool.id)}"><span><strong>${escapeHtml(tool.name)}</strong><small>${escapeHtml(tool.description)}</small></span></button>`).join('')}</div></article>`;
      }).join('')}</div>
    </section>
  `;
}
