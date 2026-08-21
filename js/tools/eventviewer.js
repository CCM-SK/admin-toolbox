import { $, escapeHtml, downloadText, dropBinder } from "../utils.js";

export function renderEventViewer(app) {

  app.innerHTML = `
    <section class="card">

      <h2>Event Viewer Analyzer</h2>

      <p class="small">
        Analyze Windows Event Viewer exports and copied event logs.
      </p>

      <div class="dropzone" id="eventDrop">
        Drop XML, LOG or TXT files here or
        <button class="btn" id="eventPick">
          Select File
        </button>

        <input
          hidden
          id="eventFile"
          type="file"
          accept=".xml,.log,.txt">
      </div>

    </section>

    <section class="card">

      <label for="eventInput">
        Event Log Content
      </label>

      <textarea
        id="eventInput"
        placeholder="Event ID: 41
Source: Kernel-Power
Level: Critical"></textarea>

      <div class="result-actions">

        <label class="checkline">
          <input
            type="checkbox"
            id="criticalOnly">
          Critical events only
        </label>

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

    <section
      class="card"
      id="eventResults"
      hidden>

      <div id="eventStats"></div>

      <div class="table-wrap">

        <table>

          <thead>
            <tr>
              <th>Event ID</th>
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

    "219": {
      category: "Kernel-PnP",
      text: "Driver initialization failed"
    },

    "6008": {
      category: "Unexpected Shutdown",
      text: "System was not shut down properly"
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

    "814": {
      category: "Intune",
      text: "Configuration policy issue"
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

  const fileInput = $("#eventFile");
  const dropZone = $("#eventDrop");

  $("#eventPick").onclick =
    () => fileInput.click();

  fileInput.onchange = () => {

    if (fileInput.files.length) {
      loadFile(fileInput.files[0]);
    }

  };

  dropBinder(dropZone, files => {

    if (files.length) {
      loadFile(files[0]);
    }

  });

  async function loadFile(file) {

    const text = await file.text();

    $("#eventInput").value = text;
  }

  function analyze() {

    findings = [];

    const text =
      $("#eventInput").value;

    const eventIds = [];

    const xmlMatches =
      text.matchAll(
        /<EventID>(\d+)<\/EventID>/gi
      );

    for (const match of xmlMatches) {
      eventIds.push(match[1]);
    }

    const classicMatches =
      text.matchAll(
        /(?:Event\s*ID|EventID)\s*[:=]?\s*(\d+)/gi
      );

    for (const match of classicMatches) {
      eventIds.push(match[1]);
    }

    const uniqueIds = [...new Set(eventIds)];

    for (const id of uniqueIds) {

      const event =
        knownEvents[id] || {
          category: "Unknown",
          text: "No rule available"
        };

      findings.push({
        id,
        category: event.category,
        description: event.text
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

    const criticalOnly =
      $("#criticalOnly").checked;

    const visibleFindings =
      criticalOnly
        ? findings.filter(x =>
            criticalIds.includes(x.id)
          )
        : findings;

    const criticalCount =
      findings.filter(x =>
        criticalIds.includes(x.id)
      ).length;

    $("#eventStats").innerHTML = `
      <div class="grid">

        <div class="stat">
          <span>Detected Events</span>
          <strong>${visibleFindings.length}</strong>
        </div>

        <div class="stat">
          <span>Critical Events</span>
          <strong>${criticalCount}</strong>
        </div>

      </div>
    `;

    if (!visibleFindings.length) {

      $("#eventTable").innerHTML = `
        <tr>
          <td colspan="3">
            No matching events found.
          </td>
        </tr>
      `;

      return;
    }

    $("#eventTable").innerHTML =
      visibleFindings.map(event => `
        <tr>

          <td>
            ${escapeHtml(event.id)}
          </td>

          <td>
            ${escapeHtml(event.category)}
          </td>

          <td>
            ${escapeHtml(event.description)}
          </td>

        </tr>
      `).join("");

  }

  document.addEventListener("change", e => {

    if (e.target.id === "criticalOnly") {
      renderResults();
    }

  });

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
