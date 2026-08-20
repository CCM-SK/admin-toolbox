import { $, escapeHtml, downloadText } from "../utils.js";

export function renderDrivers(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Driver Assistant</h2>

      <p class="small">
        Analyse Hardware-IDs from the Windows Device-Manager.
      </p>

      <label for="driverInput">Hardware IDs</label>

      <textarea
        id="driverInput"
        placeholder="PCI\\VEN_8086&DEV_51F0
USB\\VID_0BDA&PID_8153"></textarea>

      <div class="result-actions">
        <button class="btn primary" id="analyzeBtn">
          Analysieren
        </button>

        <button class="btn" id="exportBtn">
          CSV Export
        </button>
      </div>
    </section>

    <section class="card" id="driverResults" hidden>
      <h3>Gefundene Geräte</h3>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Typ</th>
              <th>Manufacturer</th>
              <th>Vendor ID</th>
              <th>Device ID</th>
              <th>Original ID</th>
              <th>Search in</th>
            </tr>
          </thead>
          <tbody id="driverTable"></tbody>
        </table>
      </div>
    </section>
  `;

  const vendorMap = {
    "8086": "Intel",
    "8087": "Intel",
    "10DE": "NVIDIA",
    "1002": "AMD",
    "1022": "AMD",
    "10EC": "Realtek",
    "0BDA": "Realtek",
    "14E4": "Broadcom",
    "168C": "Qualcomm Atheros",
    "1814": "MediaTek",
    "1028": "Dell",
    "103C": "HP",
    "1043": "ASUS",
    "1462": "MSI",
    "17AA": "Lenovo",
    "1AF4": "Red Hat",
    "15AD": "VMware"
  };

  let currentDevices = [];

  function analyze() {
    const input = $("#driverInput").value;

    const lines = input
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);

    currentDevices = [];

    for (const line of lines) {

      const pci = line.match(
        /VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})/i
      );

      const usb = line.match(
        /VID_([0-9A-F]{4}).*PID_([0-9A-F]{4})/i
      );

      if (pci) {

        const vendorId = pci[1].toUpperCase();
        const deviceId = pci[2].toUpperCase();

        currentDevices.push({
          type: "PCI",
          vendorId,
          deviceId,
          vendor: vendorMap[vendorId] || "Unknown",
          original: line
        });

      } else if (usb) {

        const vendorId = usb[1].toUpperCase();
        const deviceId = usb[2].toUpperCase();

        currentDevices.push({
          type: "USB",
          vendorId,
          deviceId,
          vendor: vendorMap[vendorId] || "Unknown",
          original: line
        });
      }
    }

    renderResults();
  }

  function renderResults() {

    const table = $("#driverTable");
    const results = $("#driverResults");

    results.hidden = false;

    if (!currentDevices.length) {

      table.innerHTML = `
        <tr>
          <td colspan="6">
            No valid Hardware IDs found.
          </td>
        </tr>
      `;

      return;
    }

    table.innerHTML = currentDevices.map(device => {

      const query = encodeURIComponent(device.original);

      return `
        <tr>
          <td>${escapeHtml(device.type)}</td>
          <td>${escapeHtml(device.vendor)}</td>
          <td>${escapeHtml(device.vendorId)}</td>
          <td>${escapeHtml(device.deviceId)}</td>

          <td class="mono">
            ${escapeHtml(device.original)}
          </td>

          <td>
            <button
              class="btn driverpack-btn"
              data-query="${query}">
              DriverPack
            </button>

            <button
              class="btn google-btn"
              data-query="${query}">
              Google
            </button>
          </td>
        </tr>
      `;
    }).join("");

    document
      .querySelectorAll(".driverpack-btn")
      .forEach(btn => {

        btn.onclick = () => {

          window.open(
            `https://driverpack.io/de/search?query=${btn.dataset.query}`,
            "_blank",
            "noopener,noreferrer"
          );

        };

      });

    document
      .querySelectorAll(".google-btn")
      .forEach(btn => {

        btn.onclick = () => {

          window.open(
            `https://www.google.com/search?q=${btn.dataset.query}`,
            "_blank",
            "noopener,noreferrer"
          );

        };

      });
  }

  $("#analyzeBtn").onclick = analyze;

  $("#exportBtn").onclick = () => {

    if (!currentDevices.length) {
      return;
    }

    const csv = [
      "Type,Vendor,VendorID,DeviceID,Original",

      ...currentDevices.map(device => [
        device.type,
        device.vendor,
        device.vendorId,
        device.deviceId,
        `"${device.original.replaceAll('"', '""')}"`
      ].join(","))
    ].join("\n");

    downloadText(
      "driver-analysis.csv",
      csv,
      "text/csv;charset=utf-8"
    );

  };
}
