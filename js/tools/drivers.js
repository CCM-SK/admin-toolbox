import { $, escapeHtml, downloadText } from "../utils.js";

export function renderDrivers(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Driver Assistant</h2>

      <p class="small">
        Paste Hardware IDs from Windows Device Manager.
        Vendor and Device IDs are detected automatically.
      </p>

      <label>Hardware IDs</label>

      <textarea id="driverInput"
        placeholder="PCI\\VEN_8086&DEV_51F0&#10;USB\\VID_0BDA&PID_8153"></textarea>

      <div class="row">
        <button class="btn primary" id="analyzeBtn">
          Analyze
        </button>

        <button class="btn" id="exportBtn">
          Export CSV
        </button>
      </div>
    </section>

    <section class="card" id="driverResults" hidden>
      <h3>Detected Devices</h3>

      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Vendor</th>
              <th>Vendor ID</th>
              <th>Device ID</th>
              <th>Original</th>
              <th>Actions</th>
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

    "17AA": "Lenovo",

    "103C": "HP",

    "1028": "Dell",

    "1043": "ASUS",

    "1462": "MSI",

    "1AF4": "Red Hat",

    "15AD": "VMware"
  };

  let currentDevices = [];

  function analyze() {
    const text = $("#driverInput").value;

    const lines = text
      .split(/\r?\n/)
      .map(x => x.trim())
      .filter(Boolean);

    currentDevices = [];

    for (const line of lines) {

      const pci = line.match(
        /VEN_([A-F0-9]{4}).*DEV_([A-F0-9]{4})/i
      );

      const usb = line.match(
        /VID[A-F0-9_([A-F0-9]{4}).*-F0-9]{4})/i
      );

      if (pci) {
        const vendorId = pci[1].toUpperCase();
        const deviceId = pci[2].toUpperCase();

        currentDevices.push({
          type: "PCI",
          vendorId,
          deviceId,
          vendor:
            vendorMap[vendorId] || "Unknown",
          original: line
        });
      }

      else if (usb) {
        const vendorId = usb[1].toUpperCase();
        const deviceId = usb[2].toUpperCase();

        currentDevices.push({
          type: "USB",
          vendorId,
          deviceId,
          vendor:
            vendorMap[vendorId] || "Unknown",
          original: line
        });
      }
    }

    renderResults();
  }

  function renderResults() {

    $("#driverResults").hidden =
      currentDevices.length === 0;

    $("#driverTable").innerHTML =
      currentDevices.map(device => {

        const driverPackQuery =
          encodeURIComponent(
            device.vendorId +
            " " +
            device.deviceId
          );

        const googleQuery =
          encodeURIComponent(
            device.original
          );

        return `
          <tr>
            <td>${device.type}</td>

            <td>
              ${escapeHtml(device.vendor)}
            </td>

            <td>
              ${escapeHtml(device.vendorId)}
            </td>

            <td>
              ${escapeHtml(device.deviceId)}
            </td>

            <td class="mono">
              ${escapeHtml(device.original)}
            </td>

            <td>

              <button
                class="btn driverpack-btn"
                data-query="${driverPackQuery}">
                DriverPack
              </button>

              <button
                class="btn google-btn"
                data-query="${googleQuery}">
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

          const query =
            btn.dataset.query;

          window.open(
            `https://driverpack.io/de/search?query=${query}`,
            "_blank",
            "noopener,noreferrer"
          );

        };

      });

    document
      .querySelectorAll(".google-btn")
      .forEach(btn => {

        btn.onclick = () => {

          const query =
            btn.dataset.query;

          window.open(
            `https://www.google.com/search?q=${query}`,
            "_blank",
            "noopener,noreferrer"
          );

        };

      });
  }

  $("#analyzeBtn").onclick = analyze;

  $("#exportBtn").onclick = () => {

    if (!currentDevices.length)
      return;

    const csv = [
      [
        "Type",
        "Vendor",
        "VendorID",
        "DeviceID",
        "Original"
      ].join(","),

      ...currentDevices.map(d =>
        [
          d.type,
          d.vendor,
          d.vendorId,
          d.deviceId,
          `"${d.original.replaceAll('"', '""')}"`
        ].join(",")
      )

    ].join("\n");

    downloadText(
      "driver-analysis.csv",
      csv,
      "text/csv;charset=utf-8"
    );

  };
}
