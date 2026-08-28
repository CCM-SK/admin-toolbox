# Security model

## Intended deployment
This repository is designed for GitHub Pages or another static-file host.

## Deliberate restrictions
- No fetch, XMLHttpRequest, WebSocket or Beacon calls are used by the app
- The HTML Content Security Policy sets connect-src 'none'
- No third-party scripts, stylesheets, fonts, analytics or tracking pixels are used
- Application code does not use cookies, localStorage, sessionStorage or IndexedDB
- Files are obtained only from explicit user actions
- Data is processed in browser memory
- Exports happen only after an explicit user click

## Important boundary
GitHub Pages serves application code to browser. The local-only applies to the files and text that the operator processes with the application. Not to the application source.

## Audit recommendations
For operational assurance case a reviewer can inspect:

1. index.html for the CSP and absence of remote origins
2. js/ for network APIs and storage APIs
3. Browser DevTools Network panel while using each tool; the application should produce no application-originated requests
4. The audit-manifest.json from the Audit page

