import { $, $$ } from './utils.js';
import { renderDashboard } from './dashboard.js';
import { renderLogs } from './tools/logs.js';
import { renderHash } from './tools/hash.js';
import { renderSubnet } from './tools/subnet.js';
import { renderPasswords } from './tools/passwords.js';
import { renderCerts } from './tools/certs.js';
import { renderDiff } from './tools/diff.js';
import { renderAudit } from './tools/audit.js';
import { renderPowershell } from './tools/powershell.js';
import { renderIdentity } from './tools/identity.js';
import { renderRegex } from './tools/regex.js';
import { renderDrivers } from "./tools/drivers.js";
import { renderHeader } from "./tools/header.js";
import { renderEventViewer } from "./tools/eventviewer.js";
import { renderSShare } from "./tools/sshare.js";
import { renderArchiveM } from "./tools/archivem.js";
import { renderSDetector } from "./tools/sdetector.js";
import { renderVlanPlanner } from './tools/vlanplanner.js';
import { renderUrlAnalyzer } from './tools/urlanalyzer.js';
import { renderEncoding } from './tools/encoding.js';
import { renderBiosInterpreter } from './tools/bios.js';
import { renderRangeAnalyzer } from './tools/range.js';
import { renderIdentityMeta } from './tools/identityMeta.js';
import { renderDataWorkbench } from './tools/jsonyamlxml.js';
import { renderJwt } from './tools/jwt.js';
import { renderTimestamp } from './tools/timestamp.js';
import { renderCron } from "./tools/cron.js";
import { renderGpResult } from './tools/gpresult.js';
import { renderCronConst } from "./tools/cron_const.js";
import { renderCiscoFirewall } from "./tools/ciscoacl.js";
import { renderDllAnalyzer } from "./tools/dlls.js";
import { renderChmod } from "./tools/chmod.js";
import { renderPaloAlto } from "./tools/paloalto.js";

const views = {
  dashboard: renderDashboard,
  logs: renderLogs,
  hash: renderHash,
  subnet: renderSubnet,
  passwords: renderPasswords,
  certs: renderCerts,
  diff: renderDiff,
  urlanalyzer: renderUrlAnalyzer,
  powershell: renderPowershell,
  identity: renderIdentity,
  regex: renderRegex,
  audit: renderAudit,
  drivers: renderDrivers,
  header: renderHeader,
  eventviewer: renderEventViewer,
  sshare: renderSShare,
  archivem: renderArchiveM,
  sdetector: renderSDetector,
  vlanplanner: renderVlanPlanner,
  encoding: renderEncoding,
  bios: renderBiosInterpreter,
  range: renderRangeAnalyzer,
  identityMeta: renderIdentityMeta,
  dataWorkbench: renderDataWorkbench,
  jwt: renderJwt,
  timestamp: renderTimestamp,
  cron: renderCron,
  gpresult: renderGpResult,
  cron_const: renderCronConst,
  ciscofirewall: renderCiscoFirewall,
  dlls: renderDllAnalyzer,
  chmod: renderChmod,
  paloalto: renderPaloAlto
};

const app = $('#app');
function activate(tool, updateHistory = true) {
  const button = document.querySelector(
    `.nav-item[data-tool="${CSS.escape(tool)}"]`
  );
  if (!button || !views[tool]) {
    tool = 'dashboard';
  }
  $$('.nav-item').forEach((item) => {
    item.classList.toggle(
      'active',
      item.dataset.tool === tool
    );
  });
  const activeButton = document.querySelector(
    `.nav-item[data-tool="${CSS.escape(tool)}"]`
  );
  const parentGroup = activeButton?.closest('.tool-group');
  if (parentGroup) {
    parentGroup.open = true;
  }
  if (updateHistory) {
    history.pushState(null, '', `#${tool}`);
  }
  views[tool](app);
}
$$('.nav-item').forEach((button) => {
  button.addEventListener('click', () => {
    activate(button.dataset.tool);
  });
});
window.addEventListener('popstate', () => {
  activate(
    location.hash.slice(1) || 'dashboard',
    false
  );
});
activate(
  location.hash.slice(1) || 'dashboard',
  false
);