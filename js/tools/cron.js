import { $, downloadText } from "../utils.js";

export function renderCron(app) {

  app.innerHTML = `
    <section class="card">

      <h2>Cron Expression Generator</h2>

      <p class="small">
        Generate standard cron expressions for Linux, Kubernetes and automation platforms.
      </p>

      <div class="grid-2">

        <div>
          <label>Minute</label>
          <input
            id="cronMinute"
            type="number"
            min="0"
            max="59"
            value="0">
        </div>

        <div>
          <label>Hour</label>
          <input
            id="cronHour"
            type="number"
            min="0"
            max="23"
            value="0">
        </div>

        <div>
          <label>Day of Month</label>
          <input
            id="cronDay"
            value="*">
        </div>

        <div>
          <label>Month</label>
          <input
            id="cronMonth"
            value="*">
        </div>

        <div>
          <label>Day of Week</label>
          <input
            id="cronWeekday"
            value="*">
        </div>

      </div>

      <div class="row">

        <button
          class="btn primary"
          id="generateCron">
          Generate
        </button>

        <button
          class="btn"
          id="copyCron">
          Copy
        </button>

        <button
          class="btn"
          id="exportCron">
          Export
        </button>

      </div>

    </section>

    <section class="card">

      <div class="stat">
        <span>Cron Expression</span>

        <strong
          id="cronResult"
          class="mono">
          0 0 * * *
        </strong>
      </div>

      <br>

      <div class="notice">
        <strong>Description:</strong>
        <span id="cronDescription">
          Every day at 00:00
        </span>
      </div>

    </section>

    <section class="card">

      <h3>Quick Templates</h3>

      <div class="row">

        <button
          class="btn cron-template"
          data-cron="*/5 * * * *">
          Every 5 Minutes
        </button>

        <button
          class="btn cron-template"
          data-cron="0 * * * *">
          Hourly
        </button>

        <button
          class="btn cron-template"
          data-cron="0 0 * * *">
          Daily
        </button>

        <button
          class="btn cron-template"
          data-cron="0 0 * * 0">
          Weekly
        </button>

        <button
          class="btn cron-template"
          data-cron="0 0 1 * *">
          Monthly
        </button>

      </div>

    </section>
  `;

  function generate() {

    const minute =
      $("#cronMinute").value || "0";

    const hour =
      $("#cronHour").value || "0";

    const day =
      $("#cronDay").value || "*";

    const month =
      $("#cronMonth").value || "*";

    const weekday =
      $("#cronWeekday").value || "*";

    const cron =
      `${minute} ${hour} ${day} ${month} ${weekday}`;

    $("#cronResult").textContent =
      cron;

    let description =
      `Runs at ${hour.padStart(2, "0")}:${minute.padStart(2, "0")}`;

    if (
      day === "*" &&
      month === "*" &&
      weekday === "*"
    ) {
      description =
        `Runs every day at ${hour.padStart(2, "0")}:${minute.padStart(2, "0")}`;
    }

    $("#cronDescription").textContent =
      description;
  }

  $("#generateCron").onclick =
    generate;

  $("#copyCron").onclick =
    async () => {

      await navigator.clipboard.writeText(
        $("#cronResult").textContent
      );

    };

  $("#exportCron").onclick = () => {

    downloadText(
      "cron-expression.txt",
      $("#cronResult").textContent
    );

  };

  document
    .querySelectorAll(".cron-template")
    .forEach(btn => {

      btn.onclick = () => {

        $("#cronResult").textContent =
          btn.dataset.cron;

      };

    });

  generate();
}
