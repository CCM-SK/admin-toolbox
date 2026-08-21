import { $, escapeHtml, downloadText, dropBinder } from "../utils.js";

export function renderEventViewer(app) {

  app.innerHTML = `
    <section class="card">

      <h2>Event Viewer Analyzer</h2>

      <p class="small">
        Analyze Windows Event Viewer exports and copied event logs.
      </p>

      <div class="dropzone" id="eventDrop">
        Drop XML event logs here or
        <button class="btn" id="eventPick">
          Select File
        </button>

        <input
          type="file"
          id="eventFile"
          accept=".xml,.txt,.log"
          hidden>
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

  const fileInput = $("#eventFile");
  const dropZone = $("#eventDrop");

  $("#eventPick").onclick = () =>
    fileInput.click();

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

  const text = $("#eventInput").value;

  const ids = [];

  const xmlMatches =
    text.matchAll(/<EventID>(\d+)<\/EventID>/gi);

  for (const match of xmlMatches) {
    ids.push(match[1]);
  }

  const textMatches =
    text.matchAll(
      /(?:Event\s*ID|EventID)\s*[:=]?\s*(\d+)/gi
    );

  for (const match of textMatches) {
    ids.push(match[1]);
  }

  for (const id of ids) {

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

      findings.push({

        id,

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

    const criticalIds =
      ["41", "6008", "1001"];

    const criticalCount =
      findings.filter(x =>
        criticalIds.includes(x.id)
      ).length;

    $("#eventStats").innerHTML = `
      <div class="grid">

        <div class="stat">
          <span>Detected Events</span>
          <strong>
            ${findings.length}
          </strong>
        </div>

        <div class="stat">
          <span>Critical Events</span>
          <strong>
            ${criticalCount}
          </strong>
        </div>

      </div>
    `;

    $("#eventTable").innerHTML =
      findings.length
      ? findings.map(x => `
        <tr>
          <td>
            ${escapeHtml(x.id)}
          </td>

          <td>
            ${escapeHtml(x.category)}
          </td>

          <td>
            ${escapeHtml(x.description)}
          </td>
        </tr>
      `).join("")
      : `
        <tr>
          <td colspan="3">
            No matching events found.
          </td>
        </tr>
      `;
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
