//! Embedded HTML/JS dashboard served from the binary.

/// Returns the full dashboard HTML as a static string, embedded at compile time.
pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloakwise — Adaptive VPN Defense</title>
<style>
  :root {
    --bg:       #0d1117;
    --surface:  #161b22;
    --border:   #30363d;
    --text:     #c9d1d9;
    --text-dim: #8b949e;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --purple:   #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: var(--bg);
    color: var(--text);
    padding: 16px;
    font-size: 13px;
    line-height: 1.5;
  }
  h1 { font-size: 18px; color: var(--accent); margin-bottom: 4px; }
  h2 { font-size: 14px; color: var(--purple); margin-bottom: 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
  .header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
  .header .sub { color: var(--text-dim); font-size: 11px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
  .stat-row { display: flex; justify-content: space-between; padding: 2px 0; }
  .stat-label { color: var(--text-dim); }
  .stat-value { color: var(--text); font-weight: bold; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; }
  .badge-green  { background: rgba(63,185,80,.15); color: var(--green); }
  .badge-yellow { background: rgba(210,153,34,.15); color: var(--yellow); }
  .badge-red    { background: rgba(248,81,73,.15);  color: var(--red); }
  .badge-blue   { background: rgba(88,166,255,.15); color: var(--accent); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; }
  th { text-align: left; color: var(--text-dim); font-size: 11px; border-bottom: 1px solid var(--border); padding: 4px 8px; }
  td { padding: 4px 8px; border-bottom: 1px solid var(--border); font-size: 12px; }
  tr:hover { background: rgba(88,166,255,.05); }
  .btn { background: var(--accent); color: #fff; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 12px; font-family: inherit; }
  .btn:hover { opacity: .85; }
  .btn-sm { padding: 3px 10px; font-size: 11px; }
  .btn-danger { background: var(--red); }
  .btn-green  { background: var(--green); }
  .btn-outline { background: none; border: 1px solid var(--border); color: var(--text); }
  .btn-outline:hover { border-color: var(--accent); color: var(--accent); }
  input, select, textarea {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    padding: 6px 10px; border-radius: 4px; font-family: inherit; font-size: 12px; width: 100%;
  }
  textarea { resize: vertical; min-height: 60px; }
  label { display: block; color: var(--text-dim); font-size: 11px; margin-bottom: 2px; margin-top: 6px; }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .tabs { display: flex; gap: 4px; margin-bottom: 12px; }
  .tab { padding: 6px 16px; border: 1px solid var(--border); border-radius: 4px 4px 0 0;
         cursor: pointer; color: var(--text-dim); background: var(--bg); }
  .tab.active { background: var(--surface); color: var(--accent); border-bottom-color: var(--surface); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  #llm-prompt { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px;
                white-space: pre-wrap; font-size: 11px; max-height: 300px; overflow-y: auto; display: none; }
  .confidence-bar { height: 6px; border-radius: 3px; background: var(--border); margin-top: 4px; }
  .confidence-fill { height: 100%; border-radius: 3px; transition: width .3s; }
  .log-line { font-size: 11px; color: var(--text-dim); padding: 1px 0; }
  .log-line .ts { color: var(--text-dim); }
  .log-line .msg { color: var(--text); }
  #event-log { max-height: 200px; overflow-y: auto; }
  .full-width { grid-column: 1 / -1; }
  .mt-8 { margin-top: 8px; }
  .mb-8 { margin-bottom: 8px; }
  .flex-between { display: flex; justify-content: space-between; align-items: center; }
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>CLOAKWISE</h1>
    <span class="sub">Adaptive VPN Cluster Defense System</span>
  </div>
  <div>
    <span id="node-id" class="badge badge-blue">—</span>
    <span id="state-badge" class="badge badge-green">—</span>
  </div>
</div>

<!-- Tabs -->
<div class="tabs">
  <div class="tab active" onclick="switchTab('dashboard')">Dashboard</div>
  <div class="tab" onclick="switchTab('profiles')">Profiles</div>
  <div class="tab" onclick="switchTab('generate')">Generate</div>
  <div class="tab" onclick="switchTab('events')">Events</div>
  <div class="tab" onclick="switchTab('deploy')">Deploy</div>
</div>

<!-- Dashboard Tab -->
<div id="tab-dashboard" class="tab-content active">
  <div class="grid">
    <div class="card">
      <h2>System Metrics</h2>
      <div class="stat-row"><span class="stat-label">Uptime</span><span class="stat-value" id="uptime">—</span></div>
      <div class="stat-row"><span class="stat-label">Events Processed</span><span class="stat-value" id="events-processed">—</span></div>
      <div class="stat-row"><span class="stat-label">Decisions Made</span><span class="stat-value" id="decisions-made">—</span></div>
      <div class="stat-row"><span class="stat-label">Profile Switches</span><span class="stat-value" id="profile-switches">—</span></div>
      <div class="stat-row"><span class="stat-label">Escalations</span><span class="stat-value" id="escalations">—</span></div>
      <div class="stat-row"><span class="stat-label">Fallback Activations</span><span class="stat-value" id="fallback-acts">—</span></div>
      <div class="stat-row"><span class="stat-label">Safe Mode Entries</span><span class="stat-value" id="safe-modes">—</span></div>
      <div class="stat-row"><span class="stat-label">Mesh (P2P)</span><span class="stat-value" id="mesh-line">—</span></div>
      <div class="stat-row"><span class="stat-label">Mesh RX / TX</span><span class="stat-value" id="mesh-pkts">—</span></div>
    </div>
    <div class="card">
      <h2>Active Profile</h2>
      <div id="active-profile-card">
        <div class="stat-row"><span class="stat-label">Name</span><span class="stat-value" id="ap-name">—</span></div>
        <div class="stat-row"><span class="stat-label">Protocol</span><span class="stat-value" id="ap-proto">—</span></div>
        <div class="stat-row"><span class="stat-label">Port</span><span class="stat-value" id="ap-port">—</span></div>
        <div class="stat-row"><span class="stat-label">Obfuscation</span><span class="stat-value" id="ap-obfs">—</span></div>
      </div>
      <div class="mt-8">
        <div class="stat-row"><span class="stat-label">AI Model</span><span class="stat-value" id="ai-status">—</span></div>
        <div class="stat-row"><span class="stat-label">Profiles Available</span><span class="stat-value" id="profiles-count">—</span></div>
        <div class="stat-row"><span class="stat-label">Burned Profiles</span><span class="stat-value" id="burned-count">—</span></div>
      </div>
    </div>
  </div>
</div>

<!-- Profiles Tab -->
<div id="tab-profiles" class="tab-content">
  <div class="card">
    <div class="flex-between mb-8">
      <h2 style="margin:0;border:0;padding:0">Registered Profiles</h2>
      <button class="btn btn-sm btn-outline" onclick="loadProfiles()">Refresh</button>
    </div>
    <table>
      <thead><tr><th>ID</th><th>Protocol</th><th>Port</th><th>Obfuscation</th><th>Max Conn</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="profiles-table"></tbody>
    </table>
  </div>
</div>

<!-- Generate Tab -->
<div id="tab-generate" class="tab-content">
  <div class="grid">
    <div class="card">
      <h2>Dynamic Profile Generator</h2>
      <label>Intent (describe what the profile should mimic)</label>
      <textarea id="gen-intent" placeholder="e.g. Mimic YouTube streaming traffic from a Russian ISP"></textarea>
      <div class="form-row">
        <div>
          <label>Protocol</label>
          <select id="gen-proto">
            <option value="xray">Xray (VLESS+Reality)</option>
            <option value="v2ray">V2Ray (VMess/VLESS)</option>
            <option value="trojan-go">Trojan-Go (Mux/CDN)</option>
            <option value="hysteria2">Hysteria 2 (QUIC)</option>
            <option value="naiveproxy">NaïveProxy (Chrome)</option>
            <option value="snowflake">Snowflake (Tor/WebRTC)</option>
            <option value="iodine">Iodine (DNS Tunnel)</option>
            <option value="briar">Briar (P2P/Mesh)</option>
            <option value="cloak">Cloak</option>
            <option value="amneziawg">AmneziaWG</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="wireguard">WireGuard</option>
          </select>
        </div>
        <div>
          <label>Mimic Service</label>
          <select id="gen-mimic">
            <option value="">Auto-detect</option>
            <option value="youtube">YouTube</option>
            <option value="netflix">Netflix</option>
            <option value="zoom">Zoom</option>
            <option value="teams">Teams</option>
            <option value="discord">Discord</option>
            <option value="steam">Steam</option>
            <option value="telegram">Telegram</option>
            <option value="whatsapp">WhatsApp</option>
            <option value="https">Generic HTTPS</option>
            <option value="websocket">Generic WebSocket</option>
          </select>
        </div>
      </div>
      <div class="form-row">
        <div>
          <label>Threat Level (0-10)</label>
          <input type="number" id="gen-threat" min="0" max="10" value="5">
        </div>
        <div>
          <label>Require TLS</label>
          <select id="gen-tls"><option value="false">No</option><option value="true">Yes</option></select>
        </div>
      </div>
      <label>Evolve From (profile ID, optional)</label>
      <input type="text" id="gen-evolve" placeholder="Leave empty to create fresh">
      <div class="mt-8">
        <button class="btn" onclick="generateProfile()">Generate Profile</button>
        <button class="btn btn-outline" onclick="buildPromptOnly()">Build LLM Prompt Only</button>
      </div>
    </div>

    <div class="card">
      <h2>Generation Result</h2>
      <div id="gen-result" style="color:var(--text-dim)">No profile generated yet.</div>
      <div id="llm-prompt" class="mt-8"></div>
    </div>
  </div>

  <div class="card mt-8">
    <h2>Generation History</h2>
    <table>
      <thead><tr><th>Profile ID</th><th>Confidence</th><th>Lifespan</th><th>Lineage</th><th>Reasoning</th></tr></thead>
      <tbody id="history-table"></tbody>
    </table>
  </div>
</div>

<!-- Events Tab -->
<div id="tab-events" class="tab-content">
  <div class="card">
    <div class="flex-between mb-8">
      <h2 style="margin:0;border:0;padding:0">Recent Telemetry Events</h2>
      <button class="btn btn-sm btn-outline" onclick="loadEvents()">Refresh</button>
    </div>
    <div id="event-log"></div>
  </div>
</div>

<!-- Deploy Tab (LLM autonomous cluster / Docker) -->
<div id="tab-deploy" class="tab-content">
  <div class="card full-width">
    <h2>Autonomous deploy</h2>
    <p class="mb-8" style="font-size:11px;color:var(--text-dim)">
      Requires <code>models.api_endpoint</code> (OpenAI-compatible). Writes files under the configured deploy workspace.
      Docker runs only if <code>deploy.allow_docker_exec</code> is true <em>and</em> you check the box below.
    </p>
    <label>Goal (natural language)</label>
    <textarea id="deploy-goal" style="min-height:100px" placeholder="e.g. Self-hosted 3-node Cloakwise cluster with Docker Compose, shared network, mount configs under /etc/cloakwise"></textarea>
    <label style="display:flex;align-items:center;gap:8px;margin-top:8px;width:auto">
      <input type="checkbox" id="deploy-docker" style="width:auto" />
      Execute docker compose (dangerous — only on trusted hosts)
    </label>
    <button class="btn mt-8" onclick="runAutonomousDeploy()">Run deploy agent</button>
    <h2 class="mt-8">Result</h2>
    <pre id="deploy-out" style="background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:11px;max-height:400px;overflow:auto;white-space:pre-wrap"></pre>
  </div>
</div>

<script>
const API = '';

function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'profiles') loadProfiles();
  if (name === 'events') loadEvents();
  if (name === 'generate') loadHistory();
}

async function runAutonomousDeploy() {
  const goal = document.getElementById('deploy-goal').value.trim();
  const execute_docker = document.getElementById('deploy-docker').checked;
  const out = document.getElementById('deploy-out');
  if (!goal) { out.textContent = 'Enter a goal.'; return; }
  out.textContent = 'Running (may take several minutes)...';
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 600000);
  try {
    const res = await fetch(API + '/api/deploy/autonomous', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ goal, execute_docker }),
      signal: ac.signal
    });
    const r = await res.json();
    clearTimeout(t);
    out.textContent = JSON.stringify(r, null, 2);
  } catch (e) {
    clearTimeout(t);
    out.textContent = 'Error: ' + e.message;
  }
}

async function fetchJson(url, opts) {
  try {
    const res = await fetch(API + url, opts);
    return await res.json();
  } catch(e) {
    console.error('Fetch error:', e);
    return { success: false, error: e.message };
  }
}

function fmtUptime(s) {
  if (!s && s !== 0) return '—';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

async function refreshStatus() {
  const r = await fetchJson('/api/status');
  if (!r.success) return;
  const d = r.data;
  document.getElementById('node-id').textContent = d.node_id;
  const sb = document.getElementById('state-badge');
  sb.textContent = d.state;
  sb.className = 'badge ' + (d.state === 'Running' ? 'badge-green' : d.state === 'SafeMode' ? 'badge-red' : 'badge-yellow');
  document.getElementById('uptime').textContent = fmtUptime(d.uptime_secs);
  document.getElementById('events-processed').textContent = d.events_processed.toLocaleString();
  document.getElementById('decisions-made').textContent = d.decisions_made.toLocaleString();
  document.getElementById('profile-switches').textContent = d.profile_switches;
  document.getElementById('escalations').textContent = d.escalations;
  document.getElementById('fallback-acts').textContent = d.fallback_activations;
  document.getElementById('safe-modes').textContent = d.safe_mode_entries;
  document.getElementById('ai-status').textContent = d.ai_model_available ? 'Online' : 'Heuristic';
  document.getElementById('profiles-count').textContent = d.profiles_available;
  document.getElementById('burned-count').textContent = d.burned_profiles;
  if (d.mesh) {
    const m = d.mesh;
    document.getElementById('mesh-line').textContent = m.enabled
      ? ((m.mapped_addr || m.listen_addr || '…') + ' · ' + Object.keys(m.peers_seen || {}).length + ' peers' + (m.encrypted ? ' · encrypted' : '') + (m.overlay && m.overlay !== 'none' ? ' · ' + m.overlay : ''))
      : 'off';
    document.getElementById('mesh-pkts').textContent = m.enabled ? (m.packets_recv + ' / ' + m.packets_sent) : '—';
  }
  if (d.active_profile) {
    document.getElementById('ap-name').textContent = d.active_profile.name;
    document.getElementById('ap-proto').textContent = d.active_profile.protocol;
    document.getElementById('ap-port').textContent = d.active_profile.port;
    document.getElementById('ap-obfs').textContent = d.active_profile.obfuscation;
  }
}

async function loadProfiles() {
  const r = await fetchJson('/api/profiles');
  if (!r.success) return;
  const tb = document.getElementById('profiles-table');
  tb.innerHTML = r.data.map(p => `<tr>
    <td>${p.id}</td><td>${p.protocol}</td><td>${p.port}</td><td>${p.obfuscation}</td><td>${p.max_concurrent}</td>
    <td>${p.is_active ? '<span class="badge badge-green">active</span>' : p.is_dynamic ? '<span class="badge badge-blue">dynamic</span>' : '<span class="badge badge-yellow">static</span>'}</td>
    <td>
      ${p.is_active ? '' : '<button class="btn btn-sm btn-green" onclick="activateProfile(\''+p.id+'\')">Activate</button> '}
      <button class="btn btn-sm btn-outline" onclick="mutateProfile('${p.id}')">Mutate</button>
      <button class="btn btn-sm btn-danger" onclick="burnProfileUI('${p.id}')">Burn</button>
    </td>
  </tr>`).join('');
}

async function loadEvents() {
  const r = await fetchJson('/api/events/recent');
  if (!r.success) return;
  const el = document.getElementById('event-log');
  if (r.data.events.length === 0) { el.innerHTML = '<div class="log-line">No recent events.</div>'; return; }
  el.innerHTML = r.data.events.map(e => {
    const type_ = e.type || 'unknown';
    return `<div class="log-line"><span class="ts">[${type_}]</span> <span class="msg">${JSON.stringify(e).substring(0,120)}</span></div>`;
  }).join('');
}

async function loadHistory() {
  const r = await fetchJson('/api/profiles/history');
  if (!r.success) return;
  const tb = document.getElementById('history-table');
  tb.innerHTML = (r.data || []).map(h => `<tr>
    <td>${h.profile_id}</td>
    <td><div class="confidence-bar"><div class="confidence-fill" style="width:${h.evasion_confidence*100}%;background:${h.evasion_confidence>.7?'var(--green)':h.evasion_confidence>.4?'var(--yellow)':'var(--red)'}"></div></div> ${(h.evasion_confidence*100).toFixed(0)}%</td>
    <td>${h.estimated_lifespan_hours}h</td>
    <td>${h.lineage_depth}</td>
    <td style="font-size:11px;color:var(--text-dim)">${h.reasoning.substring(0,80)}...</td>
  </tr>`).join('');
}

async function generateProfile() {
  const body = buildGenBody();
  const r = await fetchJson('/api/profiles/generate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if (!r.success) { document.getElementById('gen-result').innerHTML = '<span style="color:var(--red)">Error: '+r.error+'</span>'; return; }
  const d = r.data;
  document.getElementById('gen-result').innerHTML = `
    <div class="stat-row"><span class="stat-label">Profile ID</span><span class="stat-value">${d.profile.id}</span></div>
    <div class="stat-row"><span class="stat-label">Protocol</span><span class="stat-value">${d.profile.protocol}</span></div>
    <div class="stat-row"><span class="stat-label">Port</span><span class="stat-value">${d.profile.port}</span></div>
    <div class="stat-row"><span class="stat-label">Obfuscation</span><span class="stat-value">${d.profile.obfuscation}</span></div>
    <div class="stat-row"><span class="stat-label">Evasion</span><span class="stat-value">${(d.evasion_confidence*100).toFixed(0)}%</span></div>
    <div class="stat-row"><span class="stat-label">Est. Lifespan</span><span class="stat-value">${d.estimated_lifespan_hours}h</span></div>
    <p class="mt-8" style="font-size:11px;color:var(--text-dim)">${d.reasoning}</p>`;
  if (d.llm_prompt) {
    const el = document.getElementById('llm-prompt');
    el.style.display = 'block';
    el.textContent = 'SYSTEM:\n' + d.llm_prompt.system + '\n\nUSER:\n' + d.llm_prompt.user;
  }
  loadHistory();
  loadProfiles();
}

async function buildPromptOnly() {
  const body = buildGenBody();
  const r = await fetchJson('/api/llm/prompt', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
  if (!r.success) return;
  const el = document.getElementById('llm-prompt');
  el.style.display = 'block';
  el.textContent = 'SYSTEM:\n' + r.data.system + '\n\nUSER:\n' + r.data.user;
  document.getElementById('gen-result').innerHTML = '<span style="color:var(--accent)">LLM prompt built. Copy and send to your model.</span>';
}

function buildGenBody() {
  return {
    intent: document.getElementById('gen-intent').value || 'generic evasion profile',
    protocol: document.getElementById('gen-proto').value,
    mimic_service: document.getElementById('gen-mimic').value || undefined,
    threat_level: parseInt(document.getElementById('gen-threat').value) || 5,
    require_tls: document.getElementById('gen-tls').value === 'true',
    evolve_from: document.getElementById('gen-evolve').value || undefined,
  };
}

async function activateProfile(id) {
  await fetchJson('/api/profiles/'+id+'/activate', { method:'POST', headers:{'Content-Type':'application/json'}, body: '{}' });
  refreshStatus();
  loadProfiles();
}

async function mutateProfile(id) {
  const strength = prompt('Mutation strength (0.0 to 1.0):', '0.3');
  if (strength === null) return;
  await fetchJson('/api/profiles/'+id+'/mutate', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({strength: parseFloat(strength)}) });
  loadProfiles();
  loadHistory();
}

async function burnProfileUI(id) {
  const reason = prompt('Reason for burning this profile:', 'Detected by DPI');
  if (!reason) return;
  await fetchJson('/api/profiles/'+id+'/burn', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({reason}) });
  loadProfiles();
  refreshStatus();
}

// Auto-refresh
refreshStatus();
setInterval(refreshStatus, 5000);
</script>
</body>
</html>
"##;
