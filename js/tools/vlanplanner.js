function $(root, selector) {
  return root.querySelector(selector);
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function ipv4ToInt(ip) {
  const parts = String(ip).trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    const x = Number(p);
    if (x < 0 || x > 255) return null;
    n = ((n << 8) | x) >>> 0;
  }
  return n >>> 0;
}

function intToIpv4(n) {
  n = Number(n) >>> 0;
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255
  ].join(".");
}

function prefixMask(prefix) {
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function networkOf(ipInt, prefix) {
  return (ipInt & prefixMask(prefix)) >>> 0;
}

function broadcastOf(network, prefix) {
  return (network | (~prefixMask(prefix) >>> 0)) >>> 0;
}

function cidrForHosts(hosts, reserve = 2) {
  const required = Math.max(0, Number(hosts) || 0) + reserve;
  for (let prefix = 32; prefix >= 0; prefix--) {
    const addresses = 2 ** (32 - prefix);
    if (addresses >= required) return prefix;
  }
  return 0;
}

function usableCount(prefix) {
  const addresses = 2 ** (32 - prefix);
  if (prefix >= 31) return addresses;
  return Math.max(0, addresses - 2);
}

function formatRange(network, broadcast, prefix) {
  if (prefix === 31) return `${intToIpv4(network)} – ${intToIpv4(broadcast)}`;
  if (prefix === 32) return intToIpv4(network);
  return `${intToIpv4(network + 1)} – ${intToIpv4(broadcast - 1)}`;
}

function parseCidr(value) {
  const m = String(value).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,2})$/);
  if (!m) return null;
  const ip = ipv4ToInt(m[1]);
  const prefix = Number(m[2]);
  if (ip == null || prefix < 0 || prefix > 32) return null;
  const network = networkOf(ip, prefix);
  return {
    input: value,
    ip,
    prefix,
    network,
    broadcast: broadcastOf(network, prefix),
    usable: usableCount(prefix)
  };
}

function clampInt(value, min, max, fallback) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.trunc(n))) : fallback;
}

function csvEscape(v) {
  const s = String(v ?? "");
  return /[,\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadText(filename, content, type = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function banner(message, kind = "info") {
  return `<div class="notice ${kind}">${esc(message)}</div>`;
}

function renderSummaryCard(label, value, note = "") {
  return `<div class="stat"><span>${esc(label)}</span><strong>${esc(value)}</strong>${note ? `<small>${esc(note)}</small>` : ""}</div>`;
}

export function renderVlanPlanner(app) {
  app.innerHTML = `
    <section class="card">
      <h2>VLAN + subnet planner</h2>
      <p>Plan VLAN IDs and right-sized IPv4 subnets locally. Nothing is uploaded or resolved remotely.</p>

      <div class="grid">
        <label>
          Base network
          <input id="vpBase" value="10.20.0.0/16" spellcheck="false" inputmode="decimal">
          <small>IPv4 network from which planned VLANs will be allocated.</small>
        </label>

        <label>
          Number of VLANs
          <input id="vpCount" type="number" min="1" max="4094" value="8">
        </label>

        <label>
          Starting VLAN ID
          <input id="vpStartId" type="number" min="1" max="4094" value="100">
        </label>

        <label>
          Hosts per VLAN
          <input id="vpHosts" type="number" min="1" max="16777214" value="50">
          <small>Used to calculate the smallest subnet that fits each VLAN.</small>
        </label>

        <label>
          Host growth reserve
          <input id="vpReserve" type="number" min="0" max="1000000" value="2">
          <small>Extra address capacity reserved during subnet sizing.</small>
        </label>

        <label>
          Gateway convention
          <select id="vpGateway">
            <option value="first">First usable address</option>
            <option value="last">Last usable address</option>
            <option value="none">Do not assign a gateway</option>
          </select>
        </label>

        <label>
          VLAN name prefix
          <input id="vpNamePrefix" value="VLAN" maxlength="40">
        </label>

        <label>
          Allocation strategy
          <select id="vpStrategy">
            <option value="sequential">Sequential, tightly packed</option>
            <option value="aligned">Aligned on subnet boundaries</option>
          </select>
        </label>
      </div>

      <div class="actions">
        <button class="btn primary" id="vpPlan">Plan VLANs</button>
        <button class="btn" id="vpReset">Reset example</button>
        <button class="btn" id="vpCsv" disabled>Download CSV</button>
        <button class="btn" id="vpJson" disabled>Download JSON</button>
      </div>

      <div id="vpMessage"></div>
      <div id="vpSummary"></div>
      <div id="vpTable"></div>
    </section>

    <section class="card">
      <h3>Single VLAN calculator</h3>
      <p>Inspect an individual subnet and test gateway conventions.</p>

      <div class="grid">
        <label>
          VLAN ID
          <input id="svId" type="number" min="1" max="4094" value="120">
        </label>
        <label>
          VLAN name
          <input id="svName" value="Servers">
        </label>
        <label>
          Subnet
          <input id="svCidr" value="10.20.10.0/27" spellcheck="false" inputmode="decimal">
        </label>
        <label>
          Gateway
          <select id="svGateway">
            <option value="first">First usable address</option>
            <option value="last">Last usable address</option>
            <option value="none">No gateway</option>
          </select>
        </label>
      </div>

      <div class="actions">
        <button class="btn primary" id="svCalc">Calculate</button>
      </div>
      <div id="svMessage"></div>
      <div id="svResult"></div>
    </section>

    <section class="card">
      <h3>Planning notes</h3>
      <ul>
        <li>VLAN IDs are validated against the standard 1–4094 range.</li>
        <li>Subnet allocation is IPv4 only and does not modify switches, routers, DHCP, or live network services.</li>
        <li>Aligned allocation starts each subnet on its calculated CIDR boundary.</li>
        <li>Gateway assignment is a planning convention only.</li>
      </ul>
    </section>
  `;

  const state = { plan: [] };

  function clearPlanOutputs() {
    $(app, "#vpCsv").disabled = true;
    $(app, "#vpJson").disabled = true;
    $(app, "#vpSummary").innerHTML = "";
    $(app, "#vpTable").innerHTML = "";
  }

  function resetExample() {
    $(app, "#vpBase").value = "10.20.0.0/16";
    $(app, "#vpCount").value = 8;
    $(app, "#vpStartId").value = 100;
    $(app, "#vpHosts").value = 50;
    $(app, "#vpReserve").value = 2;
    $(app, "#vpGateway").value = "first";
    $(app, "#vpNamePrefix").value = "VLAN";
    $(app, "#vpStrategy").value = "sequential";
    $(app, "#vpMessage").innerHTML = "";
    clearPlanOutputs();
    state.plan = [];
  }

  function allocatePlan() {
    const parsed = parseCidr($(app, "#vpBase").value);
    const count = clampInt($(app, "#vpCount").value, 1, 4094, 8);
    const startVlan = clampInt($(app, "#vpStartId").value, 1, 4094, 100);
    const hosts = clampInt($(app, "#vpHosts").value, 1, 16777214, 50);
    const reserve = clampInt($(app, "#vpReserve").value, 0, 1000000, 2);
    const gatewayMode = $(app, "#vpGateway").value;
    const prefixText = $(app, "#vpNamePrefix").value.trim() || "VLAN";
    const strategy = $(app, "#vpStrategy").value;

    if (!parsed) throw new Error("Enter a valid IPv4 CIDR such as 10.20.0.0/16.");
    if (parsed.prefix > 30) throw new Error("The base network needs room for multiple VLAN subnets; use /30 or larger.");
    if (startVlan + count - 1 > 4094) throw new Error("The VLAN ID range exceeds 4094.");

    const prefix = cidrForHosts(hosts, reserve + 2);
    if (prefix < parsed.prefix) {
      throw new Error(`Each VLAN needs /${prefix} for ${hosts} hosts plus reserve, but the base network ${intToIpv4(parsed.network)}/${parsed.prefix} is too small for that subnet size.`);
    }

    const blockSize = 2 ** (32 - prefix);
    const baseNetwork = parsed.network;
    const baseBroadcast = parsed.broadcast;
    let cursor = baseNetwork;
    const plan = [];

    for (let i = 0; i < count; i++) {
      let network = cursor;

      if (strategy === "aligned") {
        const relative = network - baseNetwork;
        const alignedOffset = Math.ceil(relative / blockSize) * blockSize;
        network = baseNetwork + alignedOffset;
      }

      const broadcast = broadcastOf(network >>> 0, prefix);
      if (network < baseNetwork || broadcast > baseBroadcast || broadcast > 0xffffffff) {
        throw new Error(`The ${count} VLANs do not fit inside ${intToIpv4(baseNetwork)}/${parsed.prefix} using /${prefix} subnets.`);
      }

      const usable = usableCount(prefix);
      let gateway = "—";
      if (gatewayMode === "first" && prefix <= 30) gateway = intToIpv4(network + 1);
      if (gatewayMode === "last" && prefix <= 30) gateway = intToIpv4(broadcast - 1);
      if (gatewayMode === "first" && prefix === 31) gateway = intToIpv4(network);
      if (gatewayMode === "last" && prefix === 31) gateway = intToIpv4(broadcast);

      plan.push({
        vlanId: startVlan + i,
        name: `${prefixText}-${String(startVlan + i).padStart(3, "0")}`,
        cidr: `${intToIpv4(network)}/${prefix}`,
        network: intToIpv4(network),
        broadcast: intToIpv4(broadcast),
        prefix,
        usableHosts: usable,
        usableRange: formatRange(network, broadcast, prefix),
        gateway
      });

      cursor = broadcast + 1;
      if (cursor > baseBroadcast) break;
    }

    if (plan.length !== count) throw new Error("The requested VLANs do not fit inside the base network.");
    return { parsed, count, hosts, reserve, prefix, strategy, plan };
  }

  function renderPlan(result) {
    const { parsed, count, hosts, reserve, prefix, strategy, plan } = result;
    state.plan = plan;
    $(app, "#vpMessage").innerHTML = banner(
      `Planned ${count} VLANs as /${prefix} subnets from ${intToIpv4(parsed.network)}/${parsed.prefix}.`,
      "success"
    );

    const totalAddresses = plan.reduce((sum, x) => sum + (2 ** (32 - x.prefix)), 0);
    const totalUsable = plan.reduce((sum, x) => sum + x.usableHosts, 0);

    $(app, "#vpSummary").innerHTML = `
      <div class="grid">
        ${renderSummaryCard("Base network", `${intToIpv4(parsed.network)}/${parsed.prefix}`)}
        ${renderSummaryCard("Subnet size", `/${prefix}`, `${hosts} requested + ${reserve} reserve`)}
        ${renderSummaryCard("Address capacity", totalAddresses.toLocaleString())}
        ${renderSummaryCard("Usable host capacity", totalUsable.toLocaleString())}
        ${renderSummaryCard("Allocation", strategy === "aligned" ? "Aligned" : "Tightly packed")}
        ${renderSummaryCard("VLAN IDs", `${plan[0].vlanId}–${plan[plan.length - 1].vlanId}`)}
      </div>`;

    const rows = plan.map(x => `
      <tr>
        <td>${x.vlanId}</td>
        <td>${esc(x.name)}</td>
        <td class="mono">${x.cidr}</td>
        <td class="mono">${x.network}</td>
        <td class="mono">${x.broadcast}</td>
        <td>${x.usableHosts.toLocaleString()}</td>
        <td class="mono">${x.usableRange}</td>
        <td class="mono">${x.gateway}</td>
      </tr>`).join("");

    $(app, "#vpTable").innerHTML = `
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>VLAN</th><th>Name</th><th>Subnet</th><th>Network</th><th>Broadcast</th>
            <th>Usable hosts</th><th>Usable range</th><th>Gateway</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;

    $(app, "#vpCsv").disabled = false;
    $(app, "#vpJson").disabled = false;
  }

  function renderSingleVlan() {
    const id = clampInt($(app, "#svId").value, 1, 4094, 120);
    const name = $(app, "#svName").value.trim() || "VLAN";
    const cidr = parseCidr($(app, "#svCidr").value);
    const mode = $(app, "#svGateway").value;

    if (!cidr) throw new Error("Enter a valid IPv4 subnet such as 10.20.10.0/27.");
    if (id < 1 || id > 4094) throw new Error("VLAN ID must be between 1 and 4094.");

    let gateway = "—";
    if (mode === "first" && cidr.prefix <= 30) gateway = intToIpv4(cidr.network + 1);
    if (mode === "last" && cidr.prefix <= 30) gateway = intToIpv4(cidr.broadcast - 1);
    if (mode === "first" && cidr.prefix === 31) gateway = intToIpv4(cidr.network);
    if (mode === "last" && cidr.prefix === 31) gateway = intToIpv4(cidr.broadcast);

    $(app, "#svMessage").innerHTML = banner(`VLAN ${id} validated.`, "success");
    $(app, "#svResult").innerHTML = `
      <div class="grid">
        ${renderSummaryCard("VLAN ID", String(id))}
        ${renderSummaryCard("Name", name)}
        ${renderSummaryCard("CIDR", `${intToIpv4(cidr.network)}/${cidr.prefix}`)}
        ${renderSummaryCard("Mask", intToIpv4(prefixMask(cidr.prefix)))}
        ${renderSummaryCard("Network", intToIpv4(cidr.network))}
        ${renderSummaryCard("Broadcast", intToIpv4(cidr.broadcast))}
        ${renderSummaryCard("Usable hosts", cidr.usable.toLocaleString())}
        ${renderSummaryCard("Usable range", formatRange(cidr.network, cidr.broadcast, cidr.prefix))}
        ${renderSummaryCard("Gateway", gateway)}
      </div>`;
  }

  $(app, "#vpPlan").addEventListener("click", () => {
    try { renderPlan(allocatePlan()); }
    catch (e) {
      state.plan = [];
      clearPlanOutputs();
      $(app, "#vpMessage").innerHTML = banner(e.message, "error");
    }
  });

  $(app, "#vpReset").addEventListener("click", resetExample);

  $(app, "#vpCsv").addEventListener("click", () => {
    if (!state.plan.length) return;
    const header = ["VLAN ID","Name","Subnet","Network","Broadcast","Usable Hosts","Usable Range","Gateway"];
    const lines = [header.join(",")];
    for (const x of state.plan) {
      lines.push([x.vlanId,x.name,x.cidr,x.network,x.broadcast,x.usableHosts,x.usableRange,x.gateway].map(csvEscape).join(","));
    }
    downloadText("vlan-plan.csv", lines.join("\n"), "text/csv;charset=utf-8");
  });

  $(app, "#vpJson").addEventListener("click", () => {
    if (!state.plan.length) return;
    downloadText("vlan-plan.json", JSON.stringify(state.plan, null, 2), "application/json;charset=utf-8");
  });

  $(app, "#svCalc").addEventListener("click", () => {
    try { renderSingleVlan(); }
    catch (e) {
      $(app, "#svResult").innerHTML = "";
      $(app, "#svMessage").innerHTML = banner(e.message, "error");
    }
  });

  for (const sel of ["#vpBase","#vpCount","#vpStartId","#vpHosts","#vpReserve"]) {
    $(app, sel).addEventListener("keydown", e => { if (e.key === "Enter") $(app, "#vpPlan").click(); });
  }
  $(app, "#svCidr").addEventListener("keydown", e => { if (e.key === "Enter") $(app, "#svCalc").click(); });

  $(app, "#vpPlan").click();
  $(app, "#svCalc").click();
}
