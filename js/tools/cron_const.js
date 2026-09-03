import { $, downloadText } from "../utils.js";

export function renderCronConst(app) {

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
            type="text"
            value="0"
            placeholder="0-59, *, */5, 0,15,30">
        </div>

        <div>
          <label>Hour</label>
          <input
            id="cronHour"
            type="text"
            value="0"
            placeholder="0-23, *, */2, 9-17">
        </div>

        <div>
          <label>Day of Month</label>
          <input
            id="cronDay"
            type="text"
            value="*"
            placeholder="1-31, *, 1,15, */2">
        </div>

        <div>
          <label>Month</label>
          <input
            id="cronMonth"
            type="text"
            value="*"
            placeholder="1-12, JAN-DEC, *">
        </div>

        <div>
          <label>Day of Week</label>
          <input
            id="cronWeekday"
            type="text"
            value="*"
            placeholder="0-7, SUN-SAT, *">
        </div>

      </div>

      <div class="row">

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
        <strong>Interpretation:</strong>
        <span id="cronDescription">
          Runs every day at 00:00
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

  const MONTHS = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December"
  ];

  const WEEKDAYS = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday"
  ];

  function ordinal(n) {
    const num = Number(n);

    if (Number.isNaN(num)) {
      return n;
    }

    if (num % 100 >= 11 && num % 100 <= 13) {
      return `${num}th`;
    }

    switch (num % 10) {
      case 1:
        return `${num}st`;
      case 2:
        return `${num}nd`;
      case 3:
        return `${num}rd`;
      default:
        return `${num}th`;
    }
  }

  function formatTime(hour, minute) {
    const h = Number(hour);
    const m = Number(minute);

    if (Number.isNaN(h) || Number.isNaN(m)) {
      return `${hour}:${String(minute).padStart(2, "0")}`;
    }

    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
  }

  function replaceNames(value, type) {

    if (!value || value === "*") {
      return value;
    }

    const monthNames = {
      1: "January",
      2: "February",
      3: "March",
      4: "April",
      5: "May",
      6: "June",
      7: "July",
      8: "August",
      9: "September",
      10: "October",
      11: "November",
      12: "December",

      JAN: "January",
      FEB: "February",
      MAR: "March",
      APR: "April",
      MAY: "May",
      JUN: "June",
      JUL: "July",
      AUG: "August",
      SEP: "September",
      OCT: "October",
      NOV: "November",
      DEC: "December"
    };

    const weekdayNames = {
      0: "Sunday",
      1: "Monday",
      2: "Tuesday",
      3: "Wednesday",
      4: "Thursday",
      5: "Friday",
      6: "Saturday",
      7: "Sunday",

      SUN: "Sunday",
      MON: "Monday",
      TUE: "Tuesday",
      WED: "Wednesday",
      THU: "Thursday",
      FRI: "Friday",
      SAT: "Saturday"
    };

    const map =
      type === "month"
        ? monthNames
        : weekdayNames;

    return value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every value";
        }

        if (part.includes("/")) {

          const [base, step] = part.split("/");

          if (base === "*") {
            return `every ${step}`;
          }

          if (base.includes("-")) {

            const [start, end] = base.split("-");

            const translatedStart =
              map[start.toUpperCase()] ||
              map[start] ||
              start;

            const translatedEnd =
              map[end.toUpperCase()] ||
              map[end] ||
              end;

            return `${translatedStart} through ${translatedEnd} every ${step}`;
          }

          const translatedBase =
            map[base.toUpperCase()] ||
            map[base] ||
            base;

          return `${translatedBase} every ${step}`;
        }

        if (part.includes("-")) {

          const [start, end] = part.split("-");

          const translatedStart =
            map[start.toUpperCase()] ||
            map[start] ||
            start;

          const translatedEnd =
            map[end.toUpperCase()] ||
            map[end] ||
            end;

          return `${translatedStart} through ${translatedEnd}`;
        }

        /*
         * Handle a single value.
         */
        return (
          map[part.toUpperCase()] ||
          map[part] ||
          part
        );
      })
      .join(", ");
  }

  function describeMinute(value) {

    if (value === "*") {
      return "every minute";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every minute";
        }

        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} minutes`;
        }

        if (part.includes("/")) {

          const [range, step] = part.split("/");

          if (range.includes("-")) {

            const [start, end] =
              range.split("-");

            return `every ${step} minutes from minute ${start} through ${end}`;
          }

          return `every ${step} minutes from minute ${range}`;
        }

        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `every minute from ${start} through ${end}`;
        }

        return `at minute ${part}`;
      });

    return descriptions.join("; ");
  }

  function describeHour(value) {

    if (value === "*") {
      return "every hour";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every hour";
        }

        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} hours`;
        }

        if (part.includes("/")) {

          const [range, step] =
            part.split("/");

          if (range.includes("-")) {

            const [start, end] =
              range.split("-");

            return `every ${step} hours from ${start}:00 through ${end}:00`;
          }

          return `every ${step} hours from ${range}:00`;
        }

        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `every hour from ${start}:00 through ${end}:00`;
        }

        return `at ${String(part).padStart(2, "0")}:00`;
      });

    return descriptions.join("; ");
  }

  function describeDay(value) {

    if (value === "*") {
      return "";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every day";
        }

        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} days`;
        }

        if (part.includes("/")) {

          const [range, step] =
            part.split("/");

          if (range === "*") {
            return `every ${step} days`;
          }

          if (range.includes("-")) {

            const [start, end] =
              range.split("-");

            return `every ${step} days from the ${ordinal(start)} through the ${ordinal(end)} day of the month`;
          }

          return `every ${step} days starting on the ${ordinal(range)} day of the month`;
        }

        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `from the ${ordinal(start)} through the ${ordinal(end)} day of the month`;
        }

        return `on the ${ordinal(part)} day of the month`;
      });

    return descriptions.join("; ");
  }

  function describeMonth(value) {

    if (value === "*") {
      return "";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every month";
        }

        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} months`;
        }

        if (part.includes("/")) {

          const [range, step] =
            part.split("/");

          const translatedRange =
            replaceNames(range, "month");

          return `every ${step} months starting from ${translatedRange}`;
        }

        const translated =
          replaceNames(part, "month");

        if (part.includes("-")) {
          return `from ${translated}`;
        }

        return `in ${translated}`;
      });

    return descriptions.join("; ");
  }

  function describeWeekday(value) {

    if (value === "*") {
      return "";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every day of the week";
        }

        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} days of the week`;
        }

        if (part.includes("/")) {

          const [range, step] =
            part.split("/");

          const translatedRange =
            replaceNames(range, "weekday");

          return `every ${step} days on ${translatedRange}`;
        }

        const translated =
          replaceNames(part, "weekday");

        return `on ${translated}`;
      });

    return descriptions.join("; ");
  }

  function describeCron(
    minute,
    hour,
    day,
    month,
    weekday
  ) {

    if (
      (minute === "*/1" || minute === "*") &&
      hour === "*" &&
      day === "*" &&
      month === "*" &&
      weekday === "*"
    ) {
      return "Runs every minute";
    }

    if (
      minute === "*/5" &&
      hour === "*" &&
      day === "*" &&
      month === "*" &&
      weekday === "*"
    ) {
      return "Runs every 5 minutes";
    }

    if (
      minute === "0" &&
      hour === "*" &&
      day === "*" &&
      month === "*" &&
      weekday === "*"
    ) {
      return "Runs every hour at minute 00";
    }

    if (
      minute === "0" &&
      hour === "0" &&
      day === "*" &&
      month === "*" &&
      weekday === "*"
    ) {
      return "Runs every day at 00:00";
    }

    if (
      minute === "0" &&
      hour === "0" &&
      day === "*" &&
      month === "*" &&
      (
        weekday === "0" ||
        weekday === "7" ||
        weekday.toUpperCase() === "SUN"
      )
    ) {
      return "Runs every Sunday at 00:00";
    }

    if (
      minute === "0" &&
      hour === "0" &&
      day === "1" &&
      month === "*" &&
      weekday === "*"
    ) {
      return "Runs on the 1st day of every month at 00:00";
    }

    const parts = [];

    const hasComplexMinute =
      minute.includes(",") ||
      minute.includes("/") ||
      minute.includes("-") ||
      minute === "*";

    const hasComplexHour =
      hour.includes(",") ||
      hour.includes("/") ||
      hour.includes("-") ||
      hour === "*";

    if (!hasComplexMinute && !hasComplexHour) {

      parts.push(
        `at ${formatTime(hour, minute)}`
      );

    } else {

      if (hour === "*") {

        parts.push(
          describeMinute(minute)
        );

      } else if (minute === "*") {

        parts.push(
          describeHour(hour)
        );

      } else {

        parts.push(
          `${describeMinute(minute)} ${describeHour(hour)}`
        );
      }
    }

    const dayDescription =
      describeDay(day);

    const weekdayDescription =
      describeWeekday(weekday);

    const monthDescription =
      describeMonth(month);

    if (dayDescription) {
      parts.push(dayDescription);
    }

    if (weekdayDescription) {
      parts.push(weekdayDescription);
    }

    if (monthDescription) {
      parts.push(monthDescription);
    }

    return `Runs ${parts.join(" ")}`;
  }

  function generate() {

    const minute =
      $("#cronMinute").value.trim() || "0";

    const hour =
      $("#cronHour").value.trim() || "0";

    const day =
      $("#cronDay").value.trim() || "*";

    const month =
      $("#cronMonth").value.trim() || "*";

    const weekday =
      $("#cronWeekday").value.trim() || "*";

    const cron =
      `${minute} ${hour} ${day} ${month} ${weekday}`;

    $("#cronResult").textContent =
      cron;

    $("#cronDescription").textContent =
      describeCron(
        minute,
        hour,
        day,
        month,
        weekday
      );
  }

  function loadCron(cron) {

    const parts =
      cron.trim().split(/\s+/);

    if (parts.length !== 5) {
      return;
    }

    $("#cronMinute").value = parts[0];
    $("#cronHour").value = parts[1];
    $("#cronDay").value = parts[2];
    $("#cronMonth").value = parts[3];
    $("#cronWeekday").value = parts[4];

    generate();
  }

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
        loadCron(btn.dataset.cron);
      };

    });

  [
    "#cronMinute",
    "#cronHour",
    "#cronDay",
    "#cronMonth",
    "#cronWeekday"
  ].forEach(selector => {

    $(selector).addEventListener(
      "input",
      generate
    );

  });

  generate();
}