import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';
export const metadata = {
  id: 'docker-kubernetes',
    title: 'Docker & Kubernetes Inspector',
    description: 'Inspect Compose and Kubernetes manifests for configuration and security risks',
    path: '/#docker-kubernetes'
};
export function renderDockerKubernetes(app) {
  app.innerHTML = `
    <div class="tool-window" id="dockerKubernetesWindow">
  <div class="tool-window-header" id="dockerKubernetesDragHandle" title="Drag tool">
  <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
  <strong>Docker &amp; Kubernetes Inspector</strong>
  </div>
  <section class="card">
  <h2>Container configuration inspection</h2>
  <p class="small">Inspect Docker Compose and Kubernetes YAML/JSON locally. This tool does not connect to Docker or a cluster, execute workloads, fetch remote files, or apply changes. Findings are heuristic indicators, not proof of a vulnerability.</p>
  <div class="dropzone" id="dkDrop">
  Drop a YAML/JSON file here or <button class="btn" type="button" id="dkPick">Select file</button>
  <input hidden id="dkFile" type="file" accept=".yml,.yaml,.json,.txt,application/json">
  </div>
  <label for="dkInput">Configuration input</label>
  <textarea id="dkInput" rows="14" spellcheck="false" placeholder="Paste docker-compose.yml or Kubernetes manifests here..."></textarea>
  <div class="row">
  <button class="btn primary" type="button" id="dkAnalyze">Inspect configuration</button>
  <button class="btn" type="button" id="dkExampleCompose">Compose example</button>
  <button class="btn" type="button" id="dkExampleK8s">Kubernetes example</button>
  <button class="btn" type="button" id="dkClear">Clear</button>
  </div>
  <p class="small" id="dkStatus" aria-live="polite"></p>
  </section>
  <section class="card" id="dkResultCard" hidden>
  <div class="row">
  <strong>Inspection results</strong><span class="spacer"></span>
  <button class="btn" id="dkExportJson" type="button" hidden>Export JSON</button>
  <button class="btn" id="dkExportText" type="button" hidden>Download report (.txt)</button>
  </div>
  <div id="dkResults"></div>
  </section>
  </div>`;
  enableToolDragging($('#dockerKubernetesWindow'), $('#dockerKubernetesDragHandle'),
      () => document.body.classList.contains('sidebar-detached'));
  const input = $('#dkInput'), fileInput = $('#dkFile'), drop = $('#dkDrop');
  const status = $('#dkStatus'), results = $('#dkResults'), resultCard = $('#dkResultCard');
  const exportJson = $('#dkExportJson'), exportText = $('#dkExportText');
  let lastReport = null;
  $('#dkPick').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async e => {
      if (e.target.files?.[0]) await loadFile(e.target.files[0]);
  });
  drop.addEventListener('dragover', e => {
      e.preventDefault();
      e.stopPropagation();
      drop.classList.add('dragover');
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  });
  drop.addEventListener('dragleave', e => {
      e.preventDefault();
      e.stopPropagation();
      if (!drop.contains(e.relatedTarget)) drop.classList.remove('dragover');
  });
  drop.addEventListener('drop', async e => {
      e.preventDefault();
      e.stopPropagation();
      drop.classList.remove('dragover');
      const file = e.dataTransfer?.files?.[0];
      if (!file) return showStatus('No file was dropped.', 'danger');
      await loadFile(file);
  });
  async function loadFile(file) {
    if (!/\.(ya?ml|json|txt)$/i.test(file.name)) {
      showStatus('Choose a YAML, YML, JSON, or TXT file.', 'danger');
      return;
    }
    try {
      input.value = await file.text();
      fileInput.value = '';
      analyze(file.name);
    } catch {
      showStatus('Unable to read the selected file.', 'danger');
    }
  }
  $('#dkAnalyze').addEventListener('click', () => analyze('pasted configuration'));
  $('#dkExampleCompose').addEventListener('click', () => {
      input.value = composeExample();
      analyze('Compose example');
  });
  $('#dkExampleK8s').addEventListener('click', () => {
      input.value = k8sExample();
      analyze('Kubernetes example');
  });
  $('#dkClear').addEventListener('click', () => {
      input.value = '';
      fileInput.value = '';
      status.innerHTML = '';
      results.innerHTML = '';
      resultCard.hidden = true;
      exportJson.hidden = true;
      exportText.hidden = true;
      lastReport = null;
  });
  exportJson.addEventListener('click', () => {
      if (lastReport) {
        downloadText(
          'docker-kubernetes-inspection.json',
            JSON.stringify(lastReport, null, 2),
            'application/json;charset=utf-8'
        );
      }
  });
  exportText.addEventListener('click', () => {
      if (lastReport) {
        downloadText(
          'docker-kubernetes-inspection.txt',
            textReport(lastReport),
            'text/plain;charset=utf-8'
        );
      }
  });
  function analyze(source = 'pasted configuration') {
    if (!input.value.trim()) {
      lastReport = null;
      results.innerHTML = '';
      resultCard.hidden = true;
      exportJson.hidden = true;
      exportText.hidden = true;
      showStatus('Select a file or paste configuration first.', 'danger');
      return;
    }
    try {
      const docs = parseDocuments(input.value);
      const findings = [], resources = [];
      docs.forEach((doc, i) => {
          if (!obj(doc)) {
            add(findings, 'medium', 'INVALID_DOCUMENT',
                'Document is not a mapping/object',
                `Document ${i + 1} did not parse into an object.`,
                'Check YAML/JSON syntax.');
            return;
          }
          if (obj(doc.services)) {
            resources.push({
                document: i + 1,
                  kind: 'Docker Compose',
                  name: doc.name || 'Compose project'
            });
            inspectCompose(doc, findings, i + 1);
          } else if (doc.kind || doc.apiVersion) {
            resources.push({
                document: i + 1,
                  kind: doc.kind || 'Kubernetes resource',
                  name: doc.metadata?.name || '(unnamed)'
            });
            inspectK8s(doc, findings, i + 1);
          } else {
            add(findings, 'low', 'UNKNOWN_DOCUMENT',
                'Unrecognized configuration document',
                `Document ${i + 1} does not look like Compose or a Kubernetes manifest.`,
                'Check the supplied file or paste a complete manifest.');
          }
      });
      lastReport = {
        tool: 'Docker & Kubernetes Inspector',
          reportVersion: 1,
          analyzedAt: new Date().toISOString(),
          source,
          summary: {
          documents: docs.length,
            resources: resources.length,
            findings: findings.length,
            severities: counts(findings)
        },
          resources,
          findings
      };
      render(lastReport);
      resultCard.hidden = false;
      exportJson.hidden = false;
      exportText.hidden = false;
      const c = lastReport.summary.severities;
      showStatus(
        `Inspection complete: ${resources.length} resource(s), ${c.critical + c.high} high-priority, ${c.medium} medium, ${c.low} low finding(s).`,
          c.critical + c.high ? 'warn' : 'ok'
      );
    } catch (err) {
      lastReport = null;
      results.innerHTML = '';
      resultCard.hidden = true;
      exportJson.hidden = true;
      exportText.hidden = true;
      showStatus(err.message || 'Unable to parse configuration.', 'danger');
    }
  }
  function inspectCompose(root, findings, doc) {
    if (!obj(root.services)) {
      add(findings, 'medium', 'COMPOSE_SERVICES_MISSING',
          'Compose services section is missing',
          'No services mapping was found.',
          'Check the Compose structure.',
          `Document ${doc}`);
      return;
    }
    for (const [name, s] of Object.entries(root.services)) {
      const ctx = `Compose service "${name}"`;
      if (!obj(s)) {
        add(findings, 'medium', 'COMPOSE_SERVICE_INVALID',
            'Invalid service definition',
            'Service is not a mapping.',
            'Check YAML indentation.',
            ctx);
        continue;
      }
      const image = String(s.image || '');
      if (!image && !s.build) {
        add(findings, 'medium', 'IMAGE_MISSING',
            'Image/build is missing',
            'Service has neither image nor build.',
            'Specify an image or build context.',
            ctx);
      }
      if (image && floatingImage(image)) {
        add(findings, 'medium', 'FLOATING_IMAGE_TAG',
            'Floating image tag',
            `Image "${image}" is unpinned or uses latest.`,
            'Pin a version or immutable digest.',
            ctx);
      }
      if (s.privileged === true) {
        add(findings, 'critical', 'COMPOSE_PRIVILEGED',
            'Privileged container',
            'privileged: true weakens container isolation substantially.',
            'Remove privileged mode; grant only narrowly scoped capabilities.',
            ctx);
      }
      if (String(s.network_mode).toLowerCase() === 'host') {
        add(findings, 'high', 'COMPOSE_HOST_NETWORK',
            'Host networking enabled',
            'The container shares the host network namespace.',
            'Use a dedicated network and publish only required ports.',
            ctx);
      }
      if (String(s.pid).toLowerCase() === 'host') {
        add(findings, 'high', 'COMPOSE_HOST_PID',
            'Host PID namespace enabled',
            'The container can see host processes.',
            'Avoid pid: host unless strictly required.',
            ctx);
      }
      if (Array.isArray(s.cap_add) && s.cap_add.length) {
        const risky = s.cap_add.some(x =>
          /^(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)$/i.test(String(x))
        );
        add(findings, risky ? 'high' : 'medium',
            'COMPOSE_CAPABILITIES_ADDED',
            'Additional Linux capabilities',
            `cap_add: ${s.cap_add.join(', ')}.`,
            'Remove unnecessary capabilities; avoid ALL and SYS_ADMIN.',
            ctx);
      }
      for (const vol of (Array.isArray(s.volumes) ? s.volumes : [])) {
        const m = mount(vol);
        if (!m) continue;
        if (/^\/(var\/run|run)\/docker\.sock$/.test(m.source)) {
          add(findings, 'critical', 'DOCKER_SOCKET_MOUNT',
              'Docker socket mounted',
              `Mount "${String(vol)}" exposes the Docker daemon socket.`,
              'Avoid mounting the daemon socket into application containers.',
              ctx);
        } else if (m.source === '/' || /^\/(etc|root|proc|sys|dev)(\/|$)/.test(m.source)) {
          add(findings, 'high', 'SENSITIVE_HOST_MOUNT',
              'Sensitive host path mounted',
              `Host path "${m.source}" is mounted.`,
              'Remove or tightly restrict host mounts.',
              ctx);
        } else if (m.source.startsWith('/') && m.writable) {
          add(findings, 'medium', 'WRITABLE_HOST_MOUNT',
              'Writable host bind mount',
              `Mount "${String(vol)}" appears writable.`,
              'Use read-only mounts and narrow host paths.',
              ctx);
        }
      }
      for (const p of (Array.isArray(s.ports) ? s.ports : [])) {
        const port = composePort(p);
        if (port?.published && !port.ip) {
          add(findings, 'medium', 'PORT_ALL_INTERFACES',
              'Published port may bind to all interfaces',
              `Mapping "${String(p)}" has no explicit host IP.`,
              'Bind to 127.0.0.1 for local-only access or restrict exposure with firewall rules.',
              ctx);
        } else if (port?.published) {
          add(findings, 'low', 'PORT_PUBLISHED', 'Host port published',
              `Mapping "${String(p)}" exposes a host port.`, 'Confirm this service must be reachable outside its Compose network.',
              ctx);
        }
      }
      inspectEnv(s.environment, findings, ctx, 'COMPOSE');
      if (s.env_file) {
        add(findings, 'low', 'ENV_FILE_REFERENCE', 'Environment file referenced', 'An env_file may contain credentials and be accidentally committed.',
            'Keep environment files out of version control and restrict permissions.',
            ctx);
      }
      if (!obj(s.healthcheck)) add(findings, 'low', 'HEALTHCHECK_MISSING', 'Health check missing',
          'No healthcheck is configured.', 'Add an application-appropriate healthcheck where possible.', ctx);
      const limits = s.deploy?.resources?.limits;
      if (!obj(limits) || (limits.cpus === undefined && limits.memory === undefined)) add(findings, 'low', 'RESOURCE_LIMITS_MISSING', 'Resource limits are not obvious', 'No CPU/memory limits were found under deploy.resources.limits.', 'Set appropriate resource limits for the runtime and deployment mode.', ctx);
      if (s.user === 0 || /^(0|root)$/.test(String(s.user || ''))) add(findings, 'high', 'COMPOSE_ROOT_USER', 'Container runs as root', `Configured user is "${s.user}".`, 'Use a dedicated non-root user where supported.', ctx);
      if (s.read_only !== true) add(findings, 'low', 'ROOT_FS_WRITABLE', 'Writable root filesystem', 'read_only is not true.', 'Consider read_only: true and mount required writable paths separately.', ctx);
      if (JSON.stringify(s.security_opt || '').toLowerCase().includes('apparmor=unconfined')) add(findings, 'high', 'APPARMOR_UNCONFINED', 'AppArmor confinement disabled', 'security_opt includes apparmor=unconfined.', 'Use a restrictive approved profile.', ctx);
    }
  }
  function inspectK8s(r, findings, doc) {
    const kind = String(r.kind || ''), meta = r.metadata || {}, name = meta.name || '(unnamed)';
    const ctx = `${kind} "${name}" (document ${doc})`, ns = meta.namespace || 'default';
    if (!r.kind || !r.apiVersion) add(findings, 'medium', 'K8S_IDENTITY_INCOMPLETE', 'Resource identity incomplete',
        'apiVersion or kind is missing.', 'Provide the required Kubernetes identity fields.', ctx);
    if (!meta.namespace && kind !== 'Namespace' && kind !== 'CustomResourceDefinition') add(findings, 'low',
        'NAMESPACE_OMITTED', 'Namespace omitted', 'No metadata.namespace is set.',
        'Use an explicit namespace in deployment workflows.', ctx);
    const spec = podSpec(r);
    if (spec) {
      const podSC = spec.securityContext || {};
      if (spec.hostNetwork === true) add(findings, 'high', 'K8S_HOST_NETWORK', 'Host networking enabled',
          'spec.hostNetwork is true.', 'Disable host networking unless explicitly required.', ctx);
      if (spec.hostPID === true || spec.hostIPC === true) add(findings, 'high', 'K8S_HOST_NAMESPACE',
          'Host PID/IPC namespace enabled', `hostPID=${!!spec.hostPID}, hostIPC=${!!spec.hostIPC}.`,
          'Avoid sharing host namespaces unless required and approved.', ctx);
      if (spec.automountServiceAccountToken === true) add(findings, 'medium', 'TOKEN_AUTOMOUNT',
          'Service account token automount enabled', 'A Kubernetes API token may be mounted into the Pod.',
          'Disable automountServiceAccountToken when API access is unnecessary.', ctx);
      if (!spec.serviceAccountName && ns === 'default') add(findings, 'low', 'DEFAULT_SERVICE_ACCOUNT',
          'Default service account may be used', 'No serviceAccountName is specified in the default namespace.',
          'Use a dedicated least-privilege service account where appropriate.', ctx);
      if (Number(podSC.runAsUser) === 0) add(findings, 'high', 'POD_RUN_AS_ROOT', 'Pod security context sets UID 0',
          'spec.securityContext.runAsUser is 0.', 'Use a non-root UID and runAsNonRoot: true.', ctx);
      const containers = [
        ...(Array.isArray(spec.initContainers) ? spec.initContainers.map(c => ({ ...c, __type: 'initContainer' })) : []),
          ...(Array.isArray(spec.containers) ? spec.containers.map(c => ({ ...c, __type: 'container' })) : []),
          ...(Array.isArray(spec.ephemeralContainers) ? spec.ephemeralContainers.map(c => ({ ...c, __type: 'ephemeralContainer' })) : [])
      ];
      if (!containers.length) add(findings, 'medium', 'CONTAINERS_MISSING', 'No containers found',
          'No containers were found in the Pod specification.', 'Check the workload template.', ctx);
      containers.forEach(c => inspectContainer(c, podSC, findings, `${ctx} / ${c.__type} "${c.name || 'unnamed'}"`));
      for (const v of (Array.isArray(spec.volumes) ? spec.volumes : [])) {
        if (!v?.hostPath) continue;
        const path = String(v.hostPath.path || '');
        const high = path === '/' || /^\/(etc|root|var\/run|proc|sys|dev)(\/|$)/.test(path);
        add(findings, high ? 'high' : 'medium', 'HOSTPATH_VOLUME', 'hostPath volume used',
            `Volume "${v.name || '(unnamed)'}" mounts host path "${path}".`,
            'Prefer PVCs or purpose-built volumes; restrict hostPath and use read-only mounts where possible.', ctx);
      }
    }
    if (kind === 'Service') {
      if (r.spec?.type === 'NodePort') add(findings, 'medium', 'NODEPORT_SERVICE', 'NodePort service',
          'NodePort can expose a port on each node.', 'Confirm the exposure is required and restrict access.', ctx);
      if (r.spec?.type === 'LoadBalancer') add(findings, 'medium', 'LOADBALANCER_SERVICE', 'LoadBalancer service',
          'A load balancer may create an externally reachable endpoint.', 'Verify whether it is public or internal and restrict access.', ctx);
    }
    if (kind === 'Ingress') {
      if ((r.spec?.rules || []).length && !(r.spec?.tls || []).length) add(findings, 'medium', 'INGRESS_NO_TLS',
          'Ingress has no TLS configuration', 'Ingress rules exist but spec.tls is empty or missing.',
          'Configure TLS and enforce HTTPS at the ingress/controller layer.', ctx);
      for (const rule of (r.spec?.rules || [])) if (!rule.host) add(findings, 'low', 'INGRESS_HOST_MISSING',
          'Ingress host omitted', 'A rule has no hostname and may match broadly.',
          'Specify an explicit hostname where appropriate.', ctx);
    }
    if (kind === 'Secret') {
      if (Object.keys(r.data || {}).length || Object.keys(r.stringData || {}).length) add(findings, 'medium',
          'SECRET_IN_MANIFEST', 'Secret data embedded in manifest',
          'Base64 is encoding, not encryption; stringData is plaintext in this file.',
          'Avoid committing real Secret manifests. Use an approved secret workflow and encryption at rest.', ctx);
    }
    if (kind === 'ConfigMap') {
      const values = Object.entries(r.data || {}).map(([k, v]) => `${k}=${v}`).join('\n');
      if (looksSecret(values)) add(findings, 'high', 'SECRET_IN_CONFIGMAP', 'ConfigMap may contain credentials',
          'A ConfigMap value resembles a credential or private key.', 'Move secrets to an approved secret manager and rotate exposed credentials.', ctx);
    }
    if (kind === 'Role' || kind === 'ClusterRole') {
      for (const rule of (r.rules || [])) {
        if ((rule.resources || []).includes('*') || (rule.verbs || []).includes('*') || (rule.apiGroups || []).includes('*')) {
          add(findings, kind === 'ClusterRole' ? 'high' : 'medium', 'RBAC_WILDCARD', 'RBAC wildcard permission',
              'A rule uses wildcard API groups, resources, or verbs.', 'Grant only the exact resources and verbs required.', ctx);
        }
        if ((rule.resources || []).includes('secrets') && (rule.verbs || []).some(v => ['get', 'list', 'watch', '*'].includes(v))) {
          add(findings, 'high', 'RBAC_SECRET_READ', 'RBAC can read Secrets',
              'The rule grants get/list/watch or wildcard verbs on secrets.', 'Restrict Secret access to the minimum necessary.', ctx);
        }
      }
    }
  }
  function inspectContainer(c, podSC, findings, ctx) {
    const image = String(c.image || ''), sc = c.securityContext || {};
    if (!image) add(findings, 'medium', 'K8S_IMAGE_MISSING', 'Container image missing', 'No image is specified.', 'Specify a trusted image and pin a version or digest.', ctx);
    else if (floatingImage(image)) add(findings, 'medium', 'K8S_FLOATING_IMAGE', 'Floating image tag', `Image "${image}" is unpinned or uses latest.`, 'Pin a version or immutable digest.', ctx);
    if (sc.privileged === true) add(findings, 'critical', 'K8S_PRIVILEGED', 'Privileged container', 'securityContext.privileged is true.', 'Remove privileged mode and grant only specific required permissions.', ctx);
    if (sc.allowPrivilegeEscalation !== false) add(findings, 'medium', 'PRIVILEGE_ESCALATION', 'Privilege escalation not disabled', 'allowPrivilegeEscalation is not false.',
        'Set allowPrivilegeEscalation: false unless there is a documented requirement.', ctx);
    const uid = sc.runAsUser ?? podSC.runAsUser, nonRoot = sc.runAsNonRoot ?? podSC.runAsNonRoot;
    if (Number(uid) === 0) add(findings, 'high', 'CONTAINER_RUN_AS_ROOT', 'Container runs as UID 0',
        'The effective runAsUser is 0.', 'Use a non-root UID and set runAsNonRoot: true.', ctx);
    else if (nonRoot !== true) add(findings, 'medium', 'RUN_AS_NON_ROOT_MISSING', 'Non-root execution not enforced', 'runAsNonRoot is not true at container or Pod level.', 'Set runAsNonRoot: true where the image supports it.', ctx);
    if (sc.readOnlyRootFilesystem !== true) add(findings, 'low', 'READ_ONLY_ROOTFS_MISSING', 'Root filesystem is not read-only', 'readOnlyRootFilesystem is not true.',
        'Set readOnlyRootFilesystem: true and mount only required writable paths.', ctx);
    if (!obj(sc.seccompProfile) && !obj(podSC.seccompProfile)) add(findings, 'low', 'SECCOMP_UNSPECIFIED', 'Seccomp profile not explicit', 'No seccompProfile was found in the container or Pod security context.',
        'Consider RuntimeDefault or an approved seccomp profile.', ctx);
    const added = sc.capabilities?.add || [];
    if (added.length) add(findings, added.some(x => /^(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)$/i.test(String(x))) ? 'high' : 'medium', 'K8S_CAPABILITIES_ADDED', 'Additional capabilities granted', `Added capabilities: ${added.join(', ')}.`, 'Drop capabilities by default and add only what is strictly required.', ctx);
    for (const p of (c.ports || [])) if (p.hostPort) add(findings, 'medium', 'HOSTPORT_USED', 'hostPort is configured', `hostPort ${p.hostPort} binds a port on the node.`, 'Prefer Services and NetworkPolicies where possible.', ctx);
    const limits = c.resources?.limits;
    if (!obj(limits) || (!limits.cpu && !limits.memory)) add(findings, 'low', 'K8S_RESOURCE_LIMITS_MISSING', 'CPU/memory limits missing', 'No CPU or memory limit was found.', 'Set appropriate resource requests and limits.', ctx);
    inspectEnv(c.env, findings, ctx, 'K8S');
    if ((c.envFrom || []).some(x => x?.configMapRef)) add(findings, 'low', 'CONFIGMAP_ENV',
        'ConfigMap imported into environment', 'ConfigMap values are injected as environment variables.', 'Ensure ConfigMaps contain no credentials; environment variables can leak through diagnostics.', ctx);
  }
  function inspectEnv(env, findings, ctx, prefix) {
    if (Array.isArray(env)) {
      for (const item of env) {
        if (obj(item) && secretKey(item.name) && item.value != null && String(item.value) !== '') {
          const placeholder = isPlaceholder(String(item.value));
          add(findings, placeholder ? 'low' : 'high', `${prefix}_INLINE_SECRET`, 'Possible inline secret', `Environment key "${item.name}" has a literal value; the value is intentionally not shown.`, 'Use a secret manager or secret reference and do not commit real credentials.', ctx);
        }
      }
    } else if (obj(env)) {
      for (const [key, value] of Object.entries(env)) if (secretKey(key) && value != null && String(value) !== '') {
        add(findings, isPlaceholder(String(value)) ? 'low' : 'high', `${prefix}_INLINE_SECRET`, 'Possible inline secret', `Environment key "${key}" has a literal value; the value is intentionally not shown.`, 'Use a secret manager or secret reference and do not commit real credentials.', ctx);
      }
    }
  }
  function parseDocuments(text) {
    const trimmed = text.trim();
    try { const value = JSON.parse(trimmed); return Array.isArray(value) ? value : [value]; } catch {}
    return trimmed.replace(/^\uFEFF/, '').split(/^---\s*(?:#.*)?$/m).map(s => s.trim()).filter(Boolean).map(parseYaml);
      }
      function parseYaml(text) {
        const tokens = [];
        text.split(/\r?\n/).forEach((raw, i) => {
            if (!raw.trim() || /^\s*#/.test(raw) || /^\s*%YAML\b/.test(raw)) return;
                const indent = raw.match(/^ */)[0].length;
              const content = stripComment(raw.slice(indent)).trimEnd().trim();
              if (content && content !== '...') tokens.push({ indent, content, line: i + 1 });
          });
          if (!tokens.length) return {};
          const result = block(tokens, 0, tokens[0].indent);
          if (result.next < tokens.length) throw new Error(`Unsupported YAML syntax near line ${tokens[result.next].line}.`);
          return result.value;
        }
        function block(lines, start, indent) {
          const sequence = /^-(?:\s|$)/.test(lines[start].content);
          const out = sequence ? [] : {};
          let i = start;
          while (i < lines.length && lines[i].indent === indent) {
            const line = lines[i], text = line.content;
            if (sequence) {
              if (!/^-(?:\s|$)/.test(text)) break;
              const rest = text.replace(/^-\s?/, '').trim(); i++;
              if (!rest) {
                if (i < lines.length && lines[i].indent > indent) { const c = block(lines, i, lines[i].indent); out.push(c.value); i = c.next; }
                else out.push(null);
                continue;
              }
              const pair = pairAt(rest);
              if (pair) {
                const item = {}, key = unquote(pair.key), val = pair.value.trim();
                if (val) item[key] = scalar(val);
                else if (i < lines.length && lines[i].indent > indent + 1) { const c = block(lines, i, lines[i].indent); item[key] = c.value; i = c.next; }
                else item[key] = null;
                if (i < lines.length && lines[i].indent > indent) {
                  const c = block(lines, i, lines[i].indent);
                  if (obj(c.value)) Object.assign(item, c.value);
                  i = c.next;
                }
                out.push(item);
              } else {
                out.push(scalar(rest));
                if (i < lines.length && lines[i].indent > indent) { const c = block(lines, i, lines[i].indent); i = c.next; }
              }
            } else {
              if (/^-(?:\s|$)/.test(text)) break;
              const p = pairAt(text);
              if (!p) throw new Error(`Invalid YAML mapping near line ${line.line}.`);
              const key = unquote(p.key), val = p.value.trim(); i++;
              if (val === '|' || val === '>') {
                const collected = [];
                while (i < lines.length && lines[i].indent > indent) collected.push(lines[i++].content);
                out[key] = collected.join(val === '>' ? ' ' : '\n');
              } else if (val) out[key] = scalar(val);
              else if (i < lines.length && lines[i].indent > indent) { const c = block(lines, i, lines[i].indent); out[key] = c.value; i = c.next; }
              else out[key] = null;
            }
          }
          return { value: out, next: i };
        }
        function pairAt(s) {
          let quote = '', depth = 0;
          for (let i = 0; i < s.length; i++) {
            const c = s[i];
            if (quote) { if (c === quote && s[i - 1] !== '\\') quote = ''; }
            else if (c === '"' || c === "'") quote = c;
            else if (c === '[' || c === '{') depth++;
            else if (c === ']' || c === '}') depth--;
            else if (c === ':' && depth === 0 && (i === s.length - 1 || /\s/.test(s[i + 1]))) return { key: s.slice(0, i).trim(), value: s.slice(i + 1) };
          }
          return null;
        }
        function scalar(s) {
          s = s.trim();
          if (/^(null|~)$/i.test(s)) return null;
          if (/^(true|false)$/i.test(s)) return s.toLowerCase() === 'true';
          if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(s)) return Number(s);
          if ((s[0] === '"' && s.at(-1) === '"') || (s[0] === "'" && s.at(-1) === "'")) {
            if (s[0] === '"') { try { return JSON.parse(s); } catch {} }
            return s.slice(1, -1).replace(/''/g, "'");
          }
          if (s.startsWith('[') && s.endsWith(']')) return s.slice(1, -1).trim() ? flowParts(s.slice(1, -1)).map(scalar) : [];
          if (s.startsWith('{') && s.endsWith('}')) {
            const o = {};
            for (const part of flowParts(s.slice(1, -1))) { const p = pairAt(part.replace(/^([^:]+):(?=\S)/, '$1: ')); if (p) o[unquote(p.key)] = scalar(p.value); }
            return o;
          }
          return s;
        }
        function flowParts(s) {
          const out = []; let start = 0, quote = '', depth = 0;
          for (let i = 0; i < s.length; i++) {
            const c = s[i];
            if (quote) { if (c === quote && s[i - 1] !== '\\') quote = ''; }
            else if (c === '"' || c === "'") quote = c;
            else if (c === '[' || c === '{') depth++;
            else if (c === ']' || c === '}') depth--;
            else if (c === ',' && depth === 0) { out.push(s.slice(start, i).trim()); start = i + 1; }
          }
          out.push(s.slice(start).trim()); return out.filter(Boolean);
        }
        function unquote(s) {
          s = s.trim();
          return ((s[0] === '"' && s.at(-1) === '"') || (s[0] === "'" && s.at(-1) === "'")) ? s.slice(1, -1) : s;
        }
        function stripComment(s) {
          let q = '';
          for (let i = 0; i < s.length; i++) {
            const c = s[i];
            if (q) { if (c === q && s[i - 1] !== '\\') q = ''; }
            else if (c === '"' || c === "'") q = c;
            else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
          }
          return s;
        }
        function podSpec(r) {
          if (r.kind === 'Pod') return r.spec;
          if (['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job'].includes(r.kind)) return r.spec?.template?.spec;
          if (r.kind === 'CronJob') return r.spec?.jobTemplate?.spec?.template?.spec;
          return null;
        }
        function mount(v) {
          if (obj(v)) return { source: String(v.source || ''), writable: v.read_only !== true };
          if (typeof v !== 'string') return null;
          const p = v.split(':'); if (p.length < 2) return null;
          return { source: p[0], writable: !/(^|,)ro(,|$)/.test(p.slice(2).join(':')) };
        }
        function composePort(p) {
          if (obj(p)) return { ip: String(p.host_ip || ''), published: p.published != null && String(p.published) !== '' };
          if (typeof p !== 'string' && typeof p !== 'number') return null;
          const a = String(p).split(':');
          return a.length === 1 ? { ip: '', published: false } : { ip: a.length >= 3 ? a[0] : '', published: true };
        }
        function floatingImage(s) {
          s = String(s).trim(); if (!s || s.includes('@sha256:')) return false;
          const colon = s.lastIndexOf(':'); return colon <= s.lastIndexOf('/') || s.slice(colon + 1).toLowerCase() === 'latest';
        }
        function secretKey(s) {
          return /(password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|credential|access[_-]?key)/i.test(String(s || ''));
        }
        function looksSecret(s) {
          return /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}/i.test(s) ||
            /\b(password|passwd|client_secret|api_key|access_token)\s*[:=]\s*["']?[^${\s][^\s"'#]{5,}/i.test(s);
          }
          function isPlaceholder(s) {
            return /^\s*(\$\{[^}]+\}|<[^>]+>|\{\{.*\}\}|changeme|change-me|example|placeholder|dummy|redacted|\*+)\s*$/i.test(s);
        }
        function obj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
        function add(list, severity, code, title, details, recommendation, target = '') {
          list.push({ severity, code, title, details, recommendation, target: String(target || '') });
        }
        function counts(list) {
          const c = { critical: 0, high: 0, medium: 0, low: 0 };
          list.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; }); return c;
        }
        function render(report) {
          const c = report.summary.severities;
          results.innerHTML = `<div class="sub-result">
          <h3>Overview</h3><div class="grid">
          ${stat(report.summary.documents, 'Documents')}${stat(report.summary.resources, 'Recognized resources')}
          ${stat(report.findings.length, 'Findings')}${stat(c.critical + c.high, 'High priority')}
          ${stat(c.medium, 'Medium')}${stat(c.low, 'Low')}</div>
          <h3>Recognized resources</h3>${resourceTable(report.resources)}
          <h3>Findings (${report.findings.length})</h3>${findingList(report.findings)}
          <p class="small">Static heuristic inspection only. It is not a full schema validator and does not replace kubeconform, kube-linter, Checkov, Trivy, or runtime testing. YAML anchors, aliases, custom tags, and some advanced YAML syntax are not supported by this built-in parser.</p>
          </div>`;
        }
        function stat(v, label) {
          return `<div class="stat"><strong>${escapeHtml(String(v))}</strong><span>${escapeHtml(label)}</span></div>`;
        }
        function resourceTable(items) {
          if (!items.length) return '<p class="small">No recognized resources.</p>';
          return `<div class="table-wrap"><table><thead><tr><th>Document</th><th>Kind</th><th>Name</th></tr></thead><tbody>${items.map(x => `<tr><td>${x.document}</td><td>${escapeHtml(x.kind)}</td><td>${escapeHtml(x.name)}</td></tr>`).join('')}</tbody></table></div>`;
        }
        function findingList(items) {
          if (!items.length) return '<div class="status ok">No findings detected by these checks. This does not prove the configuration is secure or valid.</div>';
          const order = { critical: 0, high: 1, medium: 2, low: 3 };
          return `<div class="tool-toolbar"><label for="dkSeverity">Filter severity</label><select id="dkSeverity"><option value="all">All findings</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div><div id="dkFindingList">${[...items].sort((a,b) => order[a.severity]-order[b.severity]).map(f => {
                const css = ['critical','high'].includes(f.severity) ? 'danger' : f.severity === 'medium' ? 'warn' : '';
                return `<div class="status ${css} dk-finding" data-severity="${f.severity}" style="border:1px solid var(--line);margin:10px 0"><div class="row"><strong>${escapeHtml(f.title)}</strong><span class="pill">${f.severity.toUpperCase()}</span><span class="small">${escapeHtml(f.code)}</span></div>${f.target ? `<p><strong>Context:</strong> <code>${escapeHtml(f.target)}</code></p>` : ''}<p>${escapeHtml(f.details)}</p><p><strong>Recommendation:</strong> ${escapeHtml(f.recommendation)}</p></div>`;
            }).join('')}</div>`;
        }
        results.addEventListener('change', e => {
            if (e.target.id !== 'dkSeverity') return;
            for (const el of results.querySelectorAll('.dk-finding')) el.hidden = e.target.value !== 'all' && el.dataset.severity !== e.target.value;
        });
        function showStatus(message, type = 'ok') {
          const css = type === 'danger' ? 'danger' : type === 'warn' ? 'warn' : 'ok';
          status.innerHTML = `<div class="status ${css}" role="status">${escapeHtml(message)}</div>`;
        }
        function textReport(r) {
          const lines = ['Docker & Kubernetes Inspector', `Analyzed at: ${r.analyzedAt}`, `Source: ${r.source}`, `Documents: ${r.summary.documents}`, `Resources: ${r.summary.resources}`, `Findings: ${r.summary.findings}`, '', 'FINDINGS'];
          for (const f of r.findings) lines.push(`[${f.severity.toUpperCase()}] ${f.code}: ${f.title}`, f.target ? `Context: ${f.target}` : '', f.details, `Recommendation: ${f.recommendation}`, '');
          lines.push('Note: Heuristic report only; not a full schema validation or runtime security test.');
          return lines.join('\n');
        }
        function composeExample() {
          return `apiVersion: apps/v1
          kind: Deployment
          metadata:
          name: demo-web
          namespace: default
          spec:
          replicas: 1
          selector:
          matchLabels:
          app: demo-web
          template:
          metadata:
          labels:
          app: demo-web
          spec:
          hostNetwork: true
          containers:
          - name: web
          image: nginx:latest
          securityContext:
          privileged: true
          allowPrivilegeEscalation: true
          runAsUser: 0
          ports:
          - containerPort: 80
          hostPort: 8080
          env:
          - name: API_TOKEN
          value: inline-example-token-123456
          resources: {}
          ---
            apiVersion: v1
          kind: Service
          metadata:
          name: demo-web
          spec:
          type: NodePort
          selector:
          app: demo-web
          ports:
          - port: 80
          targetPort: 80
          nodePort: 30080
          `;
        }
        function k8sExample() {
          return `# INTENTIONALLY INSECURE STATIC-ANALYSIS FIXTURE.
# DO NOT APPLY THIS FILE TO A REAL CLUSTER.
# The credentials below are fake test values. The settings are deliberately unsafe.
---
apiVersion: v1
kind: Namespace
metadata:
  name: analyzer-insecure-fixtures
  labels:
    purpose: static-analysis-test
    security-profile: intentionally-insecure
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: analyzer-fixture-sa
  namespace: analyzer-insecure-fixtures
# Explicitly enabled to exercise analyzer rules for automatic token mounting.
automountServiceAccountToken: true
---
apiVersion: v1
kind: Secret
metadata:
  name: hardcoded-fixture-secret
  namespace: analyzer-insecure-fixtures
  labels:
    purpose: static-analysis-test
type: Opaque
# Fake values only; intended to trigger hard-coded-secret checks.
stringData:
  API_KEY: "fixture-not-a-real-secret"
  DB_PASSWORD: "password123"
---
# Deliberately over-privileged binding. Never deploy this test fixture.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: analyzer-fixture-cluster-admin
  labels:
    purpose: static-analysis-test
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: ServiceAccount
    name: analyzer-fixture-sa
    namespace: analyzer-insecure-fixtures
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: analyzer-insecure-demo
  namespace: analyzer-insecure-fixtures
  labels:
    app: analyzer-insecure-demo
    purpose: static-analysis-test
spec:
  replicas: 1
  selector:
    matchLabels:
      app: analyzer-insecure-demo
  template:
    metadata:
      labels:
        app: analyzer-insecure-demo
        purpose: static-analysis-test
    spec:
      serviceAccountName: analyzer-fixture-sa
      automountServiceAccountToken: true
      # Host namespaces reduce isolation from the node.
      hostNetwork: true
      hostPID: true
      hostIPC: true
      securityContext:
        runAsNonRoot: false
        runAsUser: 0
        seccompProfile:
          type: Unconfined
      containers:
        - name: web
          image: nginx:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 80
          # Deliberately weak container hardening for analyzer testing.
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
            capabilities:
              add:
                - ALL
          # Intentionally omitted: resource requests/limits and health probes.
          env:
            - name: DEBUG
              value: "true"
            - name: DB_PASSWORD
              value: "password123"
          volumeMounts:
            - name: host-root
              mountPath: /host
              readOnly: false
            - name: docker-socket
              mountPath: /var/run/docker.sock
              readOnly: false
      volumes:
        - name: host-root
          hostPath:
            path: /
            type: Directory
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock
            type: Socket
---
# NodePort is included to exercise externally reachable service checks.
apiVersion: v1
kind: Service
metadata:
  name: analyzer-insecure-demo
  namespace: analyzer-insecure-fixtures
  labels:
    purpose: static-analysis-test
spec:
  type: NodePort
  selector:
    app: analyzer-insecure-demo
  ports:
    - name: http
      port: 80
      targetPort: 80
      nodePort: 30080
`;
        }
      }