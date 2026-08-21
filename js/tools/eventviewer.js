import { $, escapeHtml, downloadText, dropBinder } from "../utils.js";

export function renderEventViewer(app) {

  app.innerHTML = `
    <section class="card">

      <h2>Event Viewer Analyzer Pro</h2>

      <p class="small">
        Analyze Windows Event Viewer XML exports, log files and copied events.
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
        placeholder="Paste XML export content or event log text">
      </textarea>

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

      <div class="result-actions">

        <button
          class="btn primary"
          id="analyzeEvents">
          Analyze
        </button>

        <button
          class="btn"
          id="exportJson">
          Export JSON
        </button>

        <button
          class="btn"
          id="exportCsv">
          Export CSV
        </button>

      </div>

    </section>

    <section
      id="eventResults"
      class="card"
      hidden>

      <div id="eventStats"></div>

      <div id="topSources"></div>

      <div class="table-wrap">

        <table>

          <thead>

            <tr>
              <th>Event ID</th>
              <th>Level</th>
              <th>Provider</th>
              <th>Description</th>
              <th>Timestamp</th>
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
      text: "System was not shut down correctly"
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
      text: "MDM policy problem"
    },

    "813": {
      level: "Error",
      category: "Intune",
      text: "Configuration processing failed"
    },

    "814": {
      level: "Warning",
      category: "Intune",
      text: "Configuration issue"
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
      text: "Malware cleanup failed"
    }

  };

  const levelMap = {
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information"
  };

  $("#eventPick").onclick =
    () => $("#eventFile").click();

  $("#eventFile").onchange = () => {

    const file = $("#eventFile").files[0];

    if (file) loadFile(file);

  };

  dropBinder(
    $("#eventDrop"),
    files => files[0] && loadFile(files[0])
  );

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

    const xmlEvents =
      text.match(
        /<Event[\s\S]*?<\/Event>/gi
      );

    if (xmlEvents?.length) {

      xmlEvents.forEach(eventText => {

        const eventId =
          eventText.match(
            /<EventID[^>]*>(\d+)<\/EventID>/i
          )?.[1] || "";

        const level =
          eventText.match(
            /<Level>(\d+)<\/Level>/i
          )?.[1] || "4";

        const provider =
          eventText.match(
            /Provider Name=['"]([^'"]+)/      )?.[1] || "Unknown";

        const timestamp =
          eventText.match(
            /SystemTime=[^'"]+/i
          )?.[1] || "";

        const rule =
          knownEvents[eventId];
                findings.push({

          id: eventId,

          level:
            rule?.level ||
            levelMap[level] ||
            "Information",

          provider,

          timestamp,

          description:
            rule?.text ||
            "No rule available"

        });

      });

    } else {

      const regex =
        /(?:Event\s*ID|EventID)\s*[:=]?\s*(\d+)/gi;

      let match;

      while (
        (match = regex.exec(text))
      ) {

        const id = match[1];

        const rule =
          knownEvents[id];

        findings.push({

          id,

          level:
            rule?.level ||
            "Information",

          provider:
            rule?.category ||
            "Unknown",

          timestamp: "",

          description:
            rule?.text ||
            "No rule available"

        });

      }

    }

    renderResults();
  }

  function renderResults() {

    $("#eventResults").hidden = false;

    let visible = findings.filter(x => {

      if (
        x.level === "Critical" &&
        !$("#showCritical").checked
      ) return false;

      if (
        x.level === "Error" &&
        !$("#showError").checked
      ) return false;

      if (
        x.level === "Warning" &&
        !$("#showWarning").checked
      ) return false;

      if (
        x.level === "Information" &&
        !$("#showInfo").checked
      ) return false;

      return true;

    });

    const providerCount = {};

    findings.forEach(x => {

      providerCount[x.provider] =
        (providerCount[x.provider] || 0) + 1;

    });

    const topProviders =
      Object.entries(providerCount)
        .sort((a,b)=>b[1]-a[1])
        .slice(0,10);

    const critical =
      findings.filter(
        x=>x.level==="Critical"
      ).length;

    const errors =
      findings.filter(
        x=>x.level==="Error"
      ).length;

    const warnings =
      findings.filter(
        x=>x.level==="Warning"
      ).length;

    const score =
      Math.max(
        0,
        100 -
        critical * 15 -
        errors * 5 -
        warnings
      );

    $("#eventStats").innerHTML = `

      <div class="grid">

        <div class="stat">
          <span>Health Score</span>
          <strong>${score}%</strong>
        </div>

        <div class="stat">
          <span>Total Events</span>
          <strong>${findings.length}</strong>
        </div>

        <div class="stat">
          <span>Critical</span>
          <strong>${critical}</strong>
        </div>

        <div class="stat">
          <span>Errors</span>
          <strong>${errors}</strong>
        </div>

        <div class="stat">
          <span>Warnings</span>
          <strong>${warnings}</strong>
        </div>

      </div>

    `;

    $("#topSources").innerHTML = `
      <div class="card">

        <h3>Top Event Sources</h3>

        <div class="small">
          ${topProviders
            .map(
              ([k,v]) =>
              `${escapeHtml(k)} (${v})`
            )
            .join(" • ")
          }
        </div>

      </div>
    `;

    if (!visible.length) {

      $("#eventTable").innerHTML = `
        <tr>
          <td colspan="5">
            No matching events found.
          </td>
        </tr>
      `;

      return;
    }

    $("#eventTable").innerHTML =
      visible.map(x => `

        <tr>

          <td>
            ${escapeHtml(x.id)}
          </td>

          <td>
            ${escapeHtml(x.level)}
          </td>

          <td>
            ${escapeHtml(x.provider)}
          </td>

          <td>
            ${escapeHtml(x.description)}
          </td>

          <td>
            ${escapeHtml(x.timestamp)}
          </td>

        </tr>

      `).join("");

  }

  [
    "showCritical",
    "showError",
    "showWarning",
    "showInfo"
  ].forEach(id => {

    $("#" + id)
      .addEventListener(
        "change",
        renderResults
      );

  });

  $("#analyzeEvents").onclick =
    analyze;

  $("#exportJson").onclick = () => {

    downloadText(
      "event-analysis.json",
      JSON.stringify(
        findings,
        null,
        2
      ),
      "application/json"
    );

  };

  $("#exportCsv").onclick = () => {

    const csv = [

      "EventID,Level,Provider,Description,Timestamp",

      ...findings.map(x => [

        x.id,
        x.level,
        x.provider,
        `"${x.description}"`,
        x.timestamp

      ].join(","))

    ].join("\n");

    downloadText(
      "event-analysis.csv",
      csv,
      "text/csv"
    );

  };

}
