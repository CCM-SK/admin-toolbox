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
import { renderDrivers } from "./tools/header.js";

const views={dashboard:renderDashboard,logs:renderLogs,hash:renderHash,subnet:renderSubnet,passwords:renderPasswords,certs:renderCerts,diff:renderDiff,powershell:renderPowershell,identity:renderIdentity,regex:renderRegex,audit:renderAudit,drivers: renderDrivers};
const app=$('#app');
function activate(tool){ $$('.nav-item').forEach(b=>b.classList.toggle('active',b.dataset.tool===tool)); history.replaceState(null,'',`#${tool}`); views[tool](app); }
$$('.nav-item').forEach(b=>b.addEventListener('click',()=>activate(b.dataset.tool)));
window.addEventListener('popstate',()=>activate(location.hash.slice(1)||'dashboard'));
activate(location.hash.slice(1)||'dashboard');
