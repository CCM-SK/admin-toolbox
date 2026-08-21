import { $, escapeHtml, downloadText } from "../utils.js";

export function renderEventViewer(app) {

  app.innerHTML = `
    <section class="card">

      <h2>Event Viewer Analyzer</h2>

      <p class="small">
        Analyze Event Log XML exports or copied Windows Event Viewer entries.
      </p>

      <label for="eventInput">
        Event Log Content
      </label>

      <textarea
        id="eventInput"
        placeholder="Event ID: 41
Source: Kernel-Power
Level: Critical">
      </textarea>

      <div class="result-actions">

        <button
          class="btn primary"
          id="analyzeEvents">
          Analyze
        </button>

        <button
          class="btn"
          id="exportEvents">
          Export JSON
        </button>

      </div>

    </section>

    <section class="card" id="eventResults" hidden>

      <div id="eventStats"></div>

      <div class="table-wrap">

        <table>

          <thead>
            <tr>
              <th>Event ID</th>
              <th>Source</th>
              <th>Category</th>
              <th>Description</th>
            </tr>
          </thead>

          <tbody id="eventTable"></tbody>

        </table>

      </div>

    </section>
  `;

  let findings = [];

  const knownEvents = {

    "41": {
      category: "Kernel-Power",
      text: "Unexpected restart or power loss"
    },

    "6008": {
      category: "Unexpected Shutdown",
      text: "System was not shut down properly"
    },

    "219": {
      category: "Kernel-PnP",
      text: "Driver initialization failed"
    },

    "1001": {
      category: "BugCheck",
      text: "Blue Screen detected"
    },

    "404": {
      category: "Intune",
      text: "MDM Policy Error"
    },

    "813": {
      category: "Intune",
      text: "Policy processing failed"
    },

    "20": {
      category: "Windows Update",
      text: "Update installation failed"
    },

    "25": {
      category: "Windows Update",
      text: "Update processing failed"
    },

    "1116": {
      category: "Microsoft Defender",
      text: "Malware detected"
    },

    "1117": {
      category: "Microsoft Defender",
      text: "Malware remediation failed"
    }

  };

  function analyze() {

    findings = [];

    const text = $("#eventInput").value;

    const eventRegex =
      /(?:Event\s*ID|EventID)\s*[:=]?\s*(\d+)/gi;

    let match;

    while ((match = eventRegex.exec(text)) !== null) {

      const eventId = match[1];

      const info =
        knownEvents[eventId] || {
          category: "Unknown",
          text: "No rule available"
        };

      findings.push({
        id: eventId,
        source: info.category,
        category: info.category,
        description: info.text
      });
    }

    renderResults();
  }

  function renderResults() {

    $("#eventResults").hidden = false;

    const criticalIds = [
      "41",
      "6008",
      "1001"
    ];

    const critical =
      findings.filter(x =>
        criticalIds.includes(x.id)
      ).length;

    $("#eventStats").innerHTML = `
      <div class="grid">

        <div class="stat">
          <span>Detected Events</span>
          <strong>${findings.length}</strong>
        </div>

        <div class="stat">
          <span>Critical Events</span>
          <strong>${critical}</strong>
        </div>

      </div>
    `;

    $("#eventTable").innerHTML =
      findings.map(x => `
        <tr>
          <td>${escapeHtml(x.id)}</td>
          <td>${escapeHtml(x.source)}</td>
          <td>${escapeHtml(x.category)}</td>
          <td>${escapeHtml(x.description)}</td>
        </tr>
      `).join("");

    if (!findings.length) {

      $("#eventTable").innerHTML = `
        <tr>
          <td colspan="4">
            No matching events found.
          </td>
        </tr>
      `;
    }
  }

  $("#analyzeEvents").onclick =
    analyze;

  $("#exportEvents").onclick = () => {

    if (!findings.length) {
      return;
    }

    downloadText(
      "event-analysis.json",
      JSON.stringify(
        findings,
        null,
        2
      ),
      "application/json;charset=utf-8"
    );
  };
}
