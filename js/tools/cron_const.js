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
        <strong>Description:</strong>
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

    if (num % 100 >= 11 && num % 100 <= 13) {
      return `${num}th`;
    }

    switch (num % 10) {
      case 1: return `${num}st`;
      case 2: return `${num}nd`;
      case 3: return `${num}rd`;
      default: return `${num}th`;
    }
  }

  function formatTime(hour, minute) {
    const h = Number(hour);
    const m = Number(minute);

    if (Number.isNaN(h) || Number.isNaN(m)) {
      return `${hour}:${String(minute).padStart(2, "0")}`;
    }

    // 24-hour cron time
    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
  }

  function replaceNames(value, type) {
    if (!value || value === "*") {
      return value;
    }

    const monthNames = {
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

        if (part.includes("/")) {
          const [base, step] = part.split("/");
          const translatedBase =
            map[base.toUpperCase()] || base;

          return `${translatedBase} every ${step}`;
        }

        if (part.includes("-")) {
          const [start, end] = part.split("-");

          const translatedStart =
            map[start.toUpperCase()] || start;

          const translatedEnd =
            map[end.toUpperCase()] || end;

          return `${translatedStart} through ${translatedEnd}`;
        }

        return map[part.toUpperCase()] || part;
      })
      .join(", ");
  }

  function describeMinute(value) {

    if (value === "*") {
      return "every minute";
    }

    if (value.startsWith("*/")) {
      return `every ${value.slice(2)} minutes`;
    }

    if (value.includes(",")) {
      return `at minute ${value.split(",").join(", ")}`;
    }

    if (value.includes("-")) {
      const [start, end] = value.split("-");

      if (value.includes("/")) {
        const [range, step] = value.split("/");
        const [from, to] = range.split("-");

        return `every ${step} minutes from minute ${from} through ${to}`;
      }

      return `every minute from ${start} through ${end}`;
    }

    return `at minute ${value}`;
  }

  function describeHour(value) {

    if (value === "*") {
      return "every hour";
    }

    if (value.startsWith("*/")) {
      return `every ${value.slice(2)} hours`;
    }

    if (value.includes("/")) {
      const [range, step] = value.split("/");

      if (range.includes("-")) {
        const [start, end] = range.split("-");
        return `every ${step} hours from ${start}:00 through ${end}:00`;
      }

      return `every ${step} hours`;
    }

    if (value.includes(",")) {
      return `at hours ${value.split(",").join(", ")}`;
    }

    if (value.includes("-")) {
      const [start, end] = value.split("-");
      return `every hour from ${start}:00 through ${end}:00`;
    }

    return `at ${String(value).padStart(2, "0")}:00`;
  }

  function describeDay(value) {

    if (value === "*") {
      return "";
    }

    if (value.startsWith("*/")) {
      return `every ${value.slice(2)} days`;
    }

    if (value.includes("/")) {
      const [range, step] = value.split("/");

      if (range === "*") {
        return `every ${step} days`;
      }

      return `every ${step} days within ${range}`;
    }

    if (value.includes(",")) {
      return `on days ${value.split(",").join(", ")}`;
    }

    if (value.includes("-")) {
      const [start, end] = value.split("-");
      return `from the ${ordinal(start)} through the ${ordinal(end)} day of the month`;
    }

    return `on the ${ordinal(value)} day of the month`;
  }

  function describeMonth(value) {

    if (value === "*") {
      return "";
    }

    if (value.startsWith("*/")) {
      return `every ${value.slice(2)} months`;
    }

    const translated =
      replaceNames(value, "month");

    if (value.includes(",")) {
      return `in ${translated}`;
    }

    if (value.includes("-")) {
      return `from ${translated}`;
    }

    return `in ${translated}`;
  }

  function describeWeekday(value) {

    if (value === "*") {
      return "";
    }

    if (value.startsWith("*/")) {
      return `every ${value.slice(2)} days of the week`;
    }

    const translated =
      replaceNames(value, "weekday");

    if (value.includes(",")) {
      return `on ${translated}`;
    }

    if (value.includes("-")) {
      return `on ${translated}`;
    }

    // Cron allows both 0 and 7 for Sunday
    if (value === "0" || value === "7") {
      return "on Sunday";
    }

    return `on ${translated}`;
  }

  function describeCron(
    minute,
    hour,
    day,
    month,
    weekday
  ) {

    // Common special cases

    if (
      minute === "*/1" ||
      minute === "*"
    ) {
      if (
        hour === "*" &&
        day === "*" &&
        month === "*" &&
        weekday === "*"
      ) {
        return "Runs every minute";
      }
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
      weekday === "0"
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

    // General description

    const parts = [];

    if (
      minute !== "*" &&
      !minute.includes("/") &&
      hour !== "*" &&
      !hour.includes("/")
    ) {
      parts.push(
        `at ${formatTime(hour, minute)}`
      );
    } else {
      const minuteDescription =
        describeMinute(minute);

      const hourDescription =
        describeHour(hour);

      if (hour === "*") {
        parts.push(minuteDescription);
      } else if (minute === "*") {
        parts.push(hourDescription);
      } else {
        parts.push(
          `${minuteDescription} ${hourDescription}`
        );
      }
    }

    const dayDescription =
      describeDay(day);

    const monthDescription =
      describeMonth(month);

    const weekdayDescription =
      describeWeekday(weekday);

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
        loadCron(btn.dataset.cron);
      };

    });

  // Update description dynamically as the user types.
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