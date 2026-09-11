import { $, downloadText } from "../utils.js";

/**
 * Render the Cron Expression Generator.
 *
 * This function:
 * 1. Builds the generator UI.
 * 2. Provides helpers for describing cron fields in plain English.
 * 3. Keeps the generated cron expression synchronized with the inputs.
 * 4. Supports copying, exporting, and loading predefined cron templates.
 */
export function renderCronConst(app) {

  // ---------------------------------------------------------------------------
  // Render the complete Cron Expression Generator UI.
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Lookup tables used when converting numeric cron values or abbreviations
  // into readable month/day names.
  // ---------------------------------------------------------------------------

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

  /**
   * Convert a number into its ordinal representation.
   *
   * Examples:
   *   1  -> "1st"
   *   2  -> "2nd"
   *   3  -> "3rd"
   *   4  -> "4th"
   *   11 -> "11th"
   *   22 -> "22nd"
   */
  function ordinal(n) {
    const num = Number(n);

    // Return the original value when it is not numeric.
    // This allows values such as "MON" to pass through safely.
    if (Number.isNaN(num)) {
      return n;
    }

    // 11, 12 and 13 are special cases and always use "th".
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

  /**
   * Format an hour/minute pair as HH:MM.
   *
   * Numeric values are zero-padded:
   *   9, 5 -> "09:05"
   *
   * Non-numeric values are returned in a sensible fallback format.
   */
  function formatTime(hour, minute) {
    const h = Number(hour);
    const m = Number(minute);

    if (Number.isNaN(h) || Number.isNaN(m)) {
      return `${hour}:${String(minute).padStart(2, "0")}`;
    }

    return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
  }

  /**
   * Translate month and weekday values into human-readable names.
   *
   * Supported month values include:
   *   1-12
   *   JAN-DEC
   *
   * Supported weekday values include:
   *   0-7
   *   SUN-SAT
   *
   * The function also understands simple cron constructs such as:
   *   1,15
   *   1-5
   */
  function replaceNames(value, type) {

    // "*" does not need translation.
    if (!value || value === "*") {
      return value;
    }

    // Map both numeric values and standard cron abbreviations to full names.
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

    // Select the appropriate lookup table.
    const map =
      type === "month"
        ? monthNames
        : weekdayNames;

    // Cron lists use commas, so each item is translated separately.
    return value
      .split(",")
      .map(part => {

        // A wildcard means every possible value.
        if (part === "*") {
          return "every value";
        }

        // Handle step expressions such as:
        //   */2
        //   1-10/2
        //   MON-FRI/2
        if (part.includes("/")) {

          const [base, step] = part.split("/");

          // */N means "every N".
          if (base === "*") {
            return `every ${step}`;
          }

          // Handle a stepped range.
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

          // Handle a stepped single value.
          const translatedBase =
            map[base.toUpperCase()] ||
            map[base] ||
            base;

          return `${translatedBase} every ${step}`;
        }

        // Handle ranges such as:
        //   JAN-MAR
        //   MON-FRI
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

        // Handle a single value such as JAN or MON.
        return (
          map[part.toUpperCase()] ||
          map[part] ||
          part
        );
      })
      .join(", ");
  }

  /**
   * Produce a human-readable description of the minute field.
   *
   * Examples:
   *   "*"     -> "every minute"
   *   "1-10"  -> "every minute from 1 through 10"
   *   "15"    -> "at minute 15"
   */
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

        // */N means every N minutes.
        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} minutes`;
        }

        // Handle stepped values and stepped ranges.
        if (part.includes("/")) {

          const [range, step] = part.split("/");

          if (range.includes("-")) {

            const [start, end] =
              range.split("-");

            return `every ${step} minutes from minute ${start} through ${end}`;
          }

          return `every ${step} minutes from minute ${range}`;
        }

        // Handle minute ranges.
        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `every minute from ${start} through ${end}`;
        }

        // A plain number represents a specific minute.
        return `at minute ${part}`;
      });

    return descriptions.join("; ");
  }

  /**
   * Produce a human-readable description of the hour field.
   *
   * Examples:
   *   "*"     -> "every hour"
   *   "9-17"  -> "every hour from 9:00 through 17:00"
   *   "9"     -> "at 09:00"
   */
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

        // */N means every N hours.
        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} hours`;
        }

        // Handle stepped hours and stepped ranges.
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

        // Handle an explicit hour range.
        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `every hour from ${start}:00 through ${end}:00`;
        }

        // A plain value represents a specific hour.
        return `at ${String(part).padStart(2, "0")}:00`;
      });

    return descriptions.join("; ");
  }

  /**
   * Produce a human-readable description of the day-of-month field.
   *
   * Examples:
   *   "*"      -> ""
   *   "1"      -> "on the 1st day of the month"
   *   "1-5"    -> "from the 1st through the 5th day of the month"
   */
  function describeDay(value) {

    // A wildcard does not add useful information because the expression
    // already describes the other cron fields.
    if (value === "*") {
      return "";
    }

    const descriptions = value
      .split(",")
      .map(part => {

        if (part === "*") {
          return "every day";
        }

        // */N means every N days.
        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} days`;
        }

        // Handle stepped values and ranges.
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

        // Handle an explicit day-of-month range.
        if (part.includes("-")) {

          const [start, end] =
            part.split("-");

          return `from the ${ordinal(start)} through the ${ordinal(end)} day of the month`;
        }

        // A plain value represents one specific day of the month.
        return `on the ${ordinal(part)} day of the month`;
      });

    return descriptions.join("; ");
  }

  /**
   * Produce a human-readable description of the month field.
   *
   * Examples:
   *   "*"       -> ""
   *   "JAN"     -> "in January"
   *   "JAN-MAR" -> "from January through March"
   */
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

        // */N means every N months.
        if (part.startsWith("*/")) {
          return `every ${part.slice(2)} months`;
        }

        // Handle stepped month expressions.
        if (part.includes("/")) {

          const [range, step] =
            part.split("/");

          const translatedRange =
            replaceNames(range, "month");

          return `every ${step} months starting from ${translatedRange}`;
        }

        // Translate numeric month values and JAN-DEC abbreviations.
        const translated =
          replaceNames(part, "month");

        // Ranges should be described as a range instead of "in X".
        if (part.includes("-")) {
          return `from ${translated}`;
        }

        return `in ${translated}`;
      });

    return descriptions.join("; ");
  }

  /**
   * Produce a human-readable description of the day-of-week field.
   *
   * Examples:
   *   "*"       -> ""
   *   "MON"     -> "on Monday"
   *   "MON-FRI" -> "on Monday through Friday"
   */
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

        // Handle a stepped weekday expression.
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

        // Translate numeric weekdays and SUN-SAT abbreviations.
        const translated =
          replaceNames(part, "weekday");

        return `on ${translated}`;
      });

    return descriptions.join("; ");
  }

  /**
   * Build a complete human-readable explanation of a five-field cron
   * expression.
   *
   * The function first handles common expressions with especially natural
   * wording. For everything else, it combines descriptions of the individual
   * cron fields.
   */
  function describeCron(
    minute,
    hour,
    day,
    month,
    weekday
  ) {

    // -------------------------------------------------------------------------
    // Common cron expressions get dedicated descriptions because these are
    // more natural and easier to understand than a generic field-by-field
    // explanation.
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Determine whether the minute/hour fields are simple values or contain
    // more complex cron syntax such as *, ranges, lists, or step expressions.
    // -------------------------------------------------------------------------

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

    // When both fields are simple numeric values, use a compact HH:MM format.
    if (!hasComplexMinute && !hasComplexHour) {

      parts.push(
        `at ${formatTime(hour, minute)}`
      );

    } else {

      // If the hour is unrestricted, the minute description carries the
      // useful timing information.
      if (hour === "*") {

        parts.push(
          describeMinute(minute)
        );

      // If the minute is unrestricted, describe the hour independently.
      } else if (minute === "*") {

        parts.push(
          describeHour(hour)
        );

      // Otherwise, combine both minute and hour descriptions.
      } else {

        parts.push(
          `${describeMinute(minute)} ${describeHour(hour)}`
        );
      }
    }

    // Generate descriptions for the remaining cron fields.
    const dayDescription =
      describeDay(day);

    const weekdayDescription =
      describeWeekday(weekday);

    const monthDescription =
      describeMonth(month);

    // Only append non-empty descriptions.
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

  /**
   * Read the five cron fields from the form, create the cron expression,
   * and update the result and its human-readable explanation.
   */
  function generate() {

    // Empty fields fall back to the conventional cron defaults:
    // minute/hour = 0
    // day/month/weekday = *
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

    // Standard five-field cron expression:
    // minute hour day-of-month month day-of-week
    const cron =
      `${minute} ${hour} ${day} ${month} ${weekday}`;

    // Update the generated expression shown to the user.
    $("#cronResult").textContent =
      cron;

    // Update the natural-language explanation.
    $("#cronDescription").textContent =
      describeCron(
        minute,
        hour,
        day,
        month,
        weekday
      );
  }

  /**
   * Load an existing five-field cron expression into the form.
   *
   * Invalid expressions are ignored rather than partially populating
   * the controls.
   */
  function loadCron(cron) {

    // Split on one or more whitespace characters so expressions using
    // multiple spaces are still parsed correctly.
    const parts =
      cron.trim().split(/\s+/);

    // Standard cron expressions contain exactly five fields.
    if (parts.length !== 5) {
      return;
    }

    // Populate each corresponding form field.
    $("#cronMinute").value = parts[0];
    $("#cronHour").value = parts[1];
    $("#cronDay").value = parts[2];
    $("#cronMonth").value = parts[3];
    $("#cronWeekday").value = parts[4];

    // Refresh the generated output and description.
    generate();
  }

  // ---------------------------------------------------------------------------
  // Copy button
  // ---------------------------------------------------------------------------

  // Copy the currently generated cron expression to the clipboard.
  $("#copyCron").onclick =
    async () => {

      await navigator.clipboard.writeText(
        $("#cronResult").textContent
      );

    };

  // ---------------------------------------------------------------------------
  // Export button
  // ---------------------------------------------------------------------------

  // Save the currently generated expression as a plain-text file.
  $("#exportCron").onclick = () => {

    downloadText(
      "cron-expression.txt",
      $("#cronResult").textContent
    );

  };

  // ---------------------------------------------------------------------------
  // Quick template buttons
  // ---------------------------------------------------------------------------

  // Each template stores a complete cron expression in its data-cron
  // attribute. Clicking a template loads that expression into the form.
  document
    .querySelectorAll(".cron-template")
    .forEach(btn => {

      btn.onclick = () => {
        loadCron(btn.dataset.cron);
      };

    });

  // ---------------------------------------------------------------------------
  // Live input updates
  // ---------------------------------------------------------------------------

  // Regenerate the cron expression whenever any of the five fields changes.
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

  // ---------------------------------------------------------------------------
  // Initial state
  // ---------------------------------------------------------------------------

  // Populate the initial result using the default form values.
  generate();
}