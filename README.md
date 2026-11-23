# Admin Toolbox

A static, browser-based toolbox for IT administrators. The application uses plain HTML, CSS and JavaScript modules and is designed to run from GitHub Pages or another static-file host.

## Privacy and security model

- Tool code is served as static files; tool modules are loaded on demand with same-origin ES module imports.
- Files and pasted text are processed in the browser. The application does not intentionally send this input to a server or external service.
- There is no application backend, analytics, cookie-based state, `localStorage`, `sessionStorage` or IndexedDB.
- Favorites, recently used tools and workflow artifacts exist in memory for the current tab only.
- Use **Work Canvas** to open up to 16 tools at once in independent panels. Move panels by their title bars, resize them from the lower-right corner, and minimize, maximize or close them individually. The layout is browser-only and works on GitHub Pages. The sidebar collapses automatically on entry to give the Canvas more room; use **Show tools** in the top bar to bring it back temporarily.
- In the single-tool view, use **Open in Work Canvas** to add the current tool. In Canvas mode, choose tools from the Add tool selector, grouped by space/category and sorted alphabetically by tool name. A tool can appear only once in a Canvas at a time; selecting it again focuses its existing panel.
- Detach the sidebar to move the sidebar itself; re-dock it to return to the standard layout.
- Open workflow artifacts and workspace import/export from the Workspace button in the top header.
- Workspace export is user-initiated and creates a local JSON download. Workspace files may contain sensitive text that was explicitly added to the workflow.
- Large log files (10 MiB–250 MiB) can be searched in a same-origin Web Worker using streaming reads. Large-file mode is line-oriented; CSV column analysis is available in normal mode. Filtered large-log exports are limited to 24 MiB.
- The app uses a restrictive Content Security Policy. Review `index.html` and `SECURITY.md` before deployment.

**Important:** GitHub Pages still serves the application source. “Local-only” describes how the application processes the files and text supplied to it, not the delivery of the application itself. Review the deployed source and browser Network panel for your own assurance requirements.

## Run locally

The app is static, but ES modules and Web Workers should be served over HTTP rather than opened directly as `file://` URLs. From the repository root, run a simple static server, for example:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/`. No dependency installation or build step is required to run the app.

## Deploy to GitHub Pages

1. Push the repository to GitHub.
2. In **Settings → Pages**, select the deployment source used by your repository (for example, the `main` branch and `/ (root)`).
3. Publish the repository root. No framework build step is needed.
4. Open the published Pages URL and verify that the browser console shows no module, worker or CSP errors.

All module and worker URLs are relative to their source files, so the app can run from a GitHub Pages project subpath.

## Usability features

- Use the sidebar search or press **Ctrl+K** ( **⌘K** on macOS) to search tools. Press `/` to focus search when you are not typing into a form.
- Mark tools as favorites with the star beside each tool. Favorites and the recent list are session-only.
- Tools with sample inputs show **Load example** in the tool action bar. Samples are illustrative; inspect them before using the output operationally.
- Add supported text inputs or generated reports to the in-memory workflow, then open each artifact in a compatible tool. Workflow contents remain in memory until the tab is closed or they are cleared.
- **Export Canvas** saves only the selected tools and their panel positions, sizes, stacking order and window state. **Import Canvas** restores that layout without importing tool inputs or workflow data.
- Export a full **Workspace** to preserve favorites, recent tools, the selected tool, theme, Work Canvas panel layout and workflow artifacts. Import the JSON workspace to restore them. Panel input fields are not exported automatically; add supported text to the workflow first when it needs to be included. Treat full workspace files as sensitive.

## Development checks

Node.js 20 or later is recommended for the built-in test runner and syntax checker. No runtime dependencies are required.

```bash
npm run check
```

Regenerate the static audit manifest after changing the registry:

```bash
npm run manifest
```

The syntax check deliberately excludes the unused `js/tools/citrixadcRewrite.js` module, which was left untouched as requested. The active Citrix ADC tool is `js/tools/citrixadc.js`.

## Known boundaries

- Certificate inspection decodes selected ASN.1 strings from PEM/DER input; it does not validate certificate chains, signatures, trust, revocation or OCSP/CRL status.
- Large-file log mode is line-oriented and does not perform CSV column analysis.
- Workflow integration is available for tools that declare input adapters, plus generated redacted-secret and timeline reports. It is not a general-purpose arbitrary binary pipeline.
- Work Canvas allows up to 16 simultaneous tool panels to limit browser resource use. Only one instance of each tool can be open at a time. On narrow screens, panels stack vertically rather than behaving as free-floating windows. Canvas layout export/import stores panel metadata and geometry only; it does not include text typed into any tool.
- Workspace JSON may contain log lines, configurations or other sensitive text. Store and share it securely.
