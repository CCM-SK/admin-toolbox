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

        <div class="row">

          <label class="checkline">
            <input
              type="checkbox"
              id="showCritical"
              checked>
            Critical
          </label>

          <label class="checkline">
            <input
              type="checkbox"
              id="showError"
              checked>
            Error
          </label>

          <label class="checkline">
            <input
              type="checkbox"
              id="showWarning"
              checked>
            Warning
          </label>

          <label class="checkline">
            <input
              type="checkbox"
              id="showInfo"
              checked>
            Information
          </label>

        </div>

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
              <th>Level</th>
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
      level: "Critical",
      category: "Kernel-Power",
      text: "Unexpected restart or power loss"
    },

    "6008": {
      level: "Critical",
      category: "Unexpected Shutdown",
      text: "System was not shut down properly"
    },

    "1001": {
      level: "Error",
      category: "BugCheck",
      text: "Blue Screen detected"
    },

    "219": {
      level: "Warning",
      category: "Kernel-PnP",
      text: "Driver initialization failed"
    },

    "404": {
      level: "Error",
      category: "Intune",
      text: "MDM Policy Error"
    },

    "813": {
      level: "Error",
      category: "Intune",
      text: "Policy processing failed"
    },

    "814": {
      level: "Warning",
      category: "Intune",
      text: "Configuration policy issue"
    },

    "20": {
      level: "Error",
      category: "Windows Update",
      text: "Update installation failed"
    },

    "25": {
      level: "Error",
      category: "Windows Update",
      text: "Update processing failed"
    },

    "1116": {
      level: "Critical",
      category: "Microsoft Defender",
      text: "Malware detected"
    },

    "1117": {
      level: "Error",
      category: "Microsoft Defender",
      text: "Malware remediation failed"
    }
  };

  const fileInput = $("#eventFile");
  const dropZone = $("#eventDrop");

  $("#eventPick").onclick = () => {
    fileInput.click();
  };

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

    const text =
      await file.text();

    $("#eventInput").value =
      text;

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

    const plainMatches =
      text.matchAll(
        /(?:Event\s*ID|EventID)\s*[:=]?\s*(\d+)/gi
      );

    for (const match of plainMatches) {
      eventIds.push(match[1]);
    }

    const uniqueIds =
      [...new Set(eventIds)];

    for (const id of uniqueIds) {

      const event =
        knownEvents[id] || {

          level: "Information",

          category: "Unknown",

          text:
            "No rule available"

        };

      findings.push({

        id,

        level:
          event.level,

        category:
          event.category,

        description:
          event.text

      });

    }

    renderResults();
  }

  function renderResults() {

    $("#eventResults").hidden =
      false;

    const visibleFindings =
      findings.filter(event => {

        if (
          event.level === "Critical" &&
          !$("#showCritical").checked
        ) return false;

        if (
          event.level === "Error" &&
          !$("#showError").checked
        ) return false;

        if (
          event.level === "Warning" &&
          !$("#showWarning").checked
        ) return false;

        if (
          event.level === "Information" &&
          !$("#showInfo").checked
        ) return false;

        return true;

      });

    const criticalCount =
      findings.filter(
        x => x.level === "Critical"
      ).length;

    const errorCount =
      findings.filter(
        x => x.level === "Error"
      ).length;

    const warningCount =
      findings.filter(
        x => x.level === "Warning"
      ).length;

    $("#eventStats").innerHTML = `
      <div class="grid">

        <div class="stat">
          <span>Total Events</span>
          <strong>${visibleFindings.length}</strong>
        </div>

        <div class="stat">
          <span>Critical</span>
          <strong>${criticalCount}</strong>
        </div>

        <div class="stat">
          <span>Error</span>
          <strong>${errorCount}</strong>
        </div>

        <div class="stat">
          <span>Warning</span>
          <strong>${warningCount}</strong>
        </div>

      </div>
    `;

    if (!visibleFindings.length) {

      $("#eventTable").innerHTML = `
        <tr>
          <td colspan="4">
            No matching events
