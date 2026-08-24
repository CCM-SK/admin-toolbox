Admin Toolbox is a small, browser-based IT administration toolbox. Contributions that improve its usefulness, reliability, accessibility, documentation, or security are welcome.

Getting Started:
- fork the repository.
 -create a branch for your change.
 -make your changes.
 -test the changes locally in a browser.
- open a pull request with a clear description of what you changed and why.
For small fixes, you can usually work directly in the relevant files under js/, css/, or index.html.

What We Welcome
Examples of useful contributions include:
- bug fixes and reliability improvements
- new administration or troubleshooting tools
- improvements to existing tools
- accessibility and usability improvements
- documentation improvements
- security and privacy improvements
- performance improvements

Before starting a larger feature, opening an issue first is recommended so the proposed change can be discussed.

Project Guidelines
Please keep the following principles in mind:

Local-only processing
Admin Toolbox is designed to process user data in the browser. Do not add functionality that uploads, transmits, or remotely stores user data.

Avoid introducing:

fetch
XMLHttpRequest
WebSockets or Beacon requests
Analytics or tracking
Unnecessary third-party resources
Browser storage such as localStorage or sessionStorage

These restrictions are part of the project's security model. See SECURITY.md.

Keep dependencies minimal
Prefer plain HTML, CSS, and JavaScript where practical. Avoid adding external libraries or services unless there is a strong reason and the change is reviewed first.

Follow existing style
Keep changes consistent with the existing code and UI. Prefer small, focused changes over large refactors.

Protect user data
Remember that the application may be used to inspect logs, configuration files, certificates, identifiers, and other potentially sensitive information. Test with sample or non-sensitive data whenever possible.

Testing
Before opening a pull request:
- test the affected functionality in a current browser.
- check the browser console for errors.
- verify that the change works without network access.
- make sure existing tools still work.
For security-sensitive changes, check the browser Network panel and confirm that the application does not make unexpected requests.
The application is intended for GitHub Pages or other static hosting and processes files in browser memory.

Pull Requests
Please keep pull requests focused and easy to review.
A good pull request should:
- explain what changed.
- explain why the change was needed.
- mention any important security or privacy considerations.
- include testing details.
- include screenshots or examples when they help explain a UI change.

Please avoid mixing unrelated changes into the same pull request.

Issues

When reporting a bug, include:
- what you expected to happen
- what actually happened
- steps to reproduce the problem
- browser and operating system, when relevant
- any useful error messages or screenshots

Please do not include real passwords, credentials, private keys, confidential logs, or other sensitive information in issues.

License
By contributing to this repository, you agree that your contributions may be distributed under the project's MIT License.
See LICENSE file for the full license text.
