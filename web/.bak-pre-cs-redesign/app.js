'use strict';

/* Sliver Web GUI front-end. Sidebar-driven, tabbed-detail layout modeled on the
   SHADOWFORGE console, talking to the Go bridge's REST + SSE API. */

// ---------- tiny helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
function el(tag, cls, txt) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (txt != null) e.textContent = txt;
  return e;
}
function esc(s) {
  return String(s ?? '').replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  const txt = await r.text();
  let data;
  try { data = txt ? JSON.parse(txt) : {}; } catch { data = { raw: txt }; }
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function ago(unixSec) {
  if (!unixSec) return '—';
  const d = Math.floor(Date.now() / 1000 - unixSec);
  if (d < 0) return 'in ' + fmtDur(-d);
  if (d < 5) return 'just now';
  return fmtDur(d) + ' ago';
}
function fmtDur(s) {
  if (s < 60) return s + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
function fmtSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function joinPath(base, name) {
  const sep = base.includes('\\') ? '\\' : '/';
  if (base.endsWith(sep)) return base + name;
  return base + sep + name;
}
function parentPath(p) {
  const sep = p.includes('\\') ? '\\' : '/';
  const parts = p.split(sep).filter(Boolean);
  parts.pop();
  if (sep === '/') return '/' + parts.join('/');
  return parts.join('\\') + '\\';
}
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = el('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function b64ToBlob(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return new Blob([arr]);
}

// ---------- global state ----------
const STATE = {
  agents: {},          // id -> { a, kind }
  order: [],           // display order of ids
  view: 'agents',      // agents | listeners | pivots | generate | profiles | implants | sliver
  selected: null,      // agent id shown in detail
  tab: 'terminal',
  cwd: '/',
  filter: '',
  console: {},         // id -> [ {cmd, out, err, status, ts} ]
  groupsOpen: { session: true, beacon: true, dead: true },
  interfaces: [],      // [{name, ip, version, up}] from the bridge host
};

// =====================================================================
// network interfaces (interface -> IP dropdowns)
// =====================================================================
// Fill a <select> with the bridge host's interface addresses. Option text
// shows "ip · iface" so operators pick an interface and get its IP as the
// value — the same interface→IP translation Sliver's client does for LHOST.
function fillIfaceSelect(sel, opts) {
  opts = opts || {};
  const prev = sel.value;
  sel.innerHTML = '';
  if (opts.allInterfaces) sel.appendChild(new Option('0.0.0.0 · all interfaces', '0.0.0.0'));
  if (opts.none) sel.appendChild(new Option('— none —', ''));
  for (const i of STATE.interfaces) {
    if (opts.v4only && i.version !== 4) continue;
    const label = `${i.ip} · ${i.name}${i.version === 6 ? ' (v6)' : ''}${i.up ? '' : ' [down]'}`;
    sel.appendChild(new Option(label, i.ip));
  }
  // Preserve a prior selection across refreshes; otherwise pick a sensible default.
  if (prev && Array.from(sel.options).some((o) => o.value === prev)) {
    sel.value = prev;
  } else if (opts.default != null) {
    const wanted = Array.from(sel.options).find((o) => o.value === opts.default);
    if (wanted) sel.value = opts.default;
  }
}

async function loadInterfaces() {
  try {
    STATE.interfaces = await api('GET', '/api/interfaces');
  } catch { STATE.interfaces = []; }
  // Listener bind host: default to all-interfaces (0.0.0.0).
  fillIfaceSelect($('#lst-host'), { allInterfaces: true, v4only: true, default: '0.0.0.0' });
  updateBindWarning(); // a preserved selection may itself be a VPN IP
  // Generate C2 hosts: a specific reachable IP (implants dial it), so no 0.0.0.0.
  // Prefer a real LAN interface over loopback and virtual bridges (docker/veth/…).
  const isVirtual = (n) => /^(lo|docker|br-|veth|virbr|vmnet|tun|tap|utun|zt)/i.test(n);
  const v4 = STATE.interfaces.filter((i) => i.version === 4 && i.ip !== '127.0.0.1');
  const preferred = v4.find((i) => !isVirtual(i.name)) || v4[0];
  const def = preferred ? preferred.ip : undefined;
  fillIfaceSelect($('#gen-c2-host'), { none: true, v4only: true, default: def });
  fillIfaceSelect($('#prof-c2-host'), { none: true, v4only: true, default: def });
  // Stager listener: a raw-TCP job on the bridge, same binding model as other listeners.
  fillIfaceSelect($('#stager-host'), { allInterfaces: true, v4only: true, default: '0.0.0.0' });
}

// =====================================================================
// time strip
// =====================================================================
const TZS = [
  { lbl: Intl.DateTimeFormat().resolvedOptions().timeZone.split('/').pop() || 'LOCAL', tz: undefined, utc: false },
  { lbl: 'UTC', tz: 'UTC', utc: true },
];
function fmtClock(tz, now) {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: tz, hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).format(now);
}
function tickClock() {
  const now = new Date();
  const strip = $('#timestrip');
  strip.innerHTML = '';
  for (const c of TZS) {
    const d = el('div', 'clock' + (c.utc ? ' utc' : ''));
    d.appendChild(el('span', 'lbl', c.lbl));
    d.appendChild(el('span', null, fmtClock(c.tz, now)));
    if (c.utc) d.appendChild(el('span', 'z', 'Z'));
    strip.appendChild(d);
  }
}

// =====================================================================
// top nav + view switching
// =====================================================================
// Clicking a top-nav tab always goes to that view's root — e.g. "Agents" goes
// to the dashboard even if an agent is currently selected/shown. The sidebar
// (always visible, any view) is the way back into that agent's detail; keeping
// it selected just means clicking its row re-opens the same tab you left.
$$('#topbar nav .nav').forEach((b) => {
  b.onclick = () => setView(b.dataset.view, false);
});
function setView(view, keepAgent) {
  STATE.view = view;
  if (view !== 'agents' && location.hash !== '#' + view) location.hash = view;
  else if (view === 'agents' && !STATE.selected && location.hash) location.hash = '';
  $$('#topbar nav .nav').forEach((x) => x.classList.toggle('active', x.dataset.view === view));
  $$('#main > .view').forEach((v) => v.classList.remove('active'));
  const agentView = $('#agent-view');
  agentView.classList.remove('active');

  if (view === 'agents') {
    if (STATE.selected && keepAgent !== false && STATE.agents[STATE.selected]) {
      agentView.classList.add('active');
    } else {
      $('#view-agents').classList.add('active');
    }
  } else {
    $('#view-' + view).classList.add('active');
    if (view === 'listeners') { loadJobs(); loadStagerProfiles(); }
    else if (view === 'pivots') loadPivotGraph();
    else if (view === 'profiles') loadProfiles();
    else if (view === 'implants') loadImplants();
    else if (view === 'sliver') loadSliver();
  }
}

// =====================================================================
// theme (light / dark), persisted
// =====================================================================
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  const btn = $('#theme-toggle');
  if (btn) btn.innerHTML = t === 'light' ? '&#9728;' : '&#9790;'; // ☀ / ☾
}
function initTheme() {
  applyTheme(localStorage.getItem('sliver.theme') || 'dark');
  $('#theme-toggle').onclick = () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    localStorage.setItem('sliver.theme', next);
    applyTheme(next);
  };
}

// =====================================================================
// customizable tab order (drag a top-nav tab to reorder; persisted)
// =====================================================================
const TAB_ORDER_KEY = 'sliver.tabOrder';

function saveTabOrder() {
  localStorage.setItem(TAB_ORDER_KEY, JSON.stringify($$('#topbar nav .nav').map((b) => b.dataset.view)));
}
function applyTabOrder() {
  const nav = $('#topbar nav');
  let order;
  try { order = JSON.parse(localStorage.getItem(TAB_ORDER_KEY)); } catch { order = null; }
  if (!Array.isArray(order)) return;
  const byView = {};
  $$('#topbar nav .nav').forEach((b) => { byView[b.dataset.view] = b; });
  // Append in saved order; any tab missing from the saved list (e.g. a newly
  // added one) is left in place and ends up after the ordered ones.
  order.forEach((v) => { if (byView[v]) nav.appendChild(byView[v]); });
}
function initTabReorder() {
  applyTabOrder();
  let dragged = null;
  $$('#topbar nav .nav').forEach((b) => {
    b.draggable = true;
    b.title = 'drag to reorder';
    b.addEventListener('dragstart', (e) => {
      dragged = b; b.classList.add('dragging'); e.dataTransfer.effectAllowed = 'move';
    });
    b.addEventListener('dragend', () => {
      b.classList.remove('dragging'); dragged = null;
      $$('#topbar nav .nav').forEach((x) => x.classList.remove('drop-target'));
    });
    b.addEventListener('dragover', (e) => {
      if (!dragged || dragged === b) return;
      e.preventDefault(); b.classList.add('drop-target');
    });
    b.addEventListener('dragleave', () => b.classList.remove('drop-target'));
    b.addEventListener('drop', (e) => {
      e.preventDefault(); b.classList.remove('drop-target');
      if (!dragged || dragged === b) return;
      const items = $$('#topbar nav .nav');
      if (items.indexOf(dragged) < items.indexOf(b)) b.after(dragged);
      else b.before(dragged);
      saveTabOrder();
    });
  });
}

// =====================================================================
// readline-style command inputs (bash-like history + Tab completion)
// =====================================================================
// Shared behavior for the two command prompts (agent terminal + Sliver console):
//   Up / Down  cycle through previously entered commands
//   Tab        complete the command word against a known-command list
function longestCommonPrefix(arr) {
  if (!arr.length) return '';
  let p = arr[0];
  for (const s of arr) {
    while (!s.startsWith(p)) p = p.slice(0, -1);
    if (!p) break;
  }
  return p;
}
function caretToEnd(input) {
  const n = input.value.length;
  // Defer so the value is committed before we move the caret.
  requestAnimationFrame(() => input.setSelectionRange(n, n));
}
function tabComplete(input, commands, onList) {
  const val = input.value;
  if (/\s/.test(val) || !val) return;           // only complete the first (command) word
  const matches = commands.filter((c) => c.startsWith(val));
  if (!matches.length) return;
  if (matches.length === 1) { input.value = matches[0] + ' '; return; }
  const lcp = longestCommonPrefix(matches);
  if (lcp.length > val.length) input.value = lcp;
  if (onList) onList(matches);
}
// Attaches history + completion to an input. `commands` may be an array or a
// function returning one. Returns { remember(line) } to be called on submit.
function makeConsoleInput(input, commands, onList) {
  const history = [];
  let idx = 0;      // cursor into history; === history.length means "live draft"
  let draft = '';
  const cmds = () => (typeof commands === 'function' ? commands() : commands);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
      if (!history.length) return;
      e.preventDefault();
      if (idx === history.length) draft = input.value;
      idx = Math.max(0, idx - 1);
      input.value = history[idx];
      caretToEnd(input);
    } else if (e.key === 'ArrowDown') {
      if (idx >= history.length) return;
      e.preventDefault();
      idx = Math.min(history.length, idx + 1);
      input.value = idx === history.length ? draft : history[idx];
      caretToEnd(input);
    } else if (e.key === 'Tab') {
      e.preventDefault();
      tabComplete(input, cmds(), onList);
    }
  });
  return {
    remember(line) {
      if (line && history[history.length - 1] !== line) history.push(line);
      if (history.length > 200) history.shift();
      idx = history.length;
      draft = '';
    },
  };
}

const TERM_COMMANDS = ['cat', 'cd', 'clear', 'download', 'ea', 'execute', 'execute-assembly',
  'help', 'ifconfig', 'info', 'interactive', 'kill', 'ls', 'mkdir', 'netstat', 'ps', 'pwd',
  'rm', 'run', 'screenshot', 'shell', 'upload', 'whoami'];
const SV_COMMANDS = ['agents', 'background', 'beacons', 'bg', 'cd', 'clear', 'ea', 'execute',
  'execute-assembly', 'help', 'ifconfig', 'info', 'interactive', 'jobs', 'kill', 'ls', 'netstat',
  'ps', 'pwd', 'screenshot', 'sessions', 'shell', 'use'];

// =====================================================================
// sidebar + agents
// =====================================================================
$('#agent-refresh').onclick = loadAgents;
$('#agent-filter').addEventListener('input', (e) => {
  STATE.filter = e.target.value.toLowerCase();
  renderSidebar();
});

async function loadAgents() {
  try {
    const [sessions, beacons] = await Promise.all([
      api('GET', '/api/sessions'),
      api('GET', '/api/beacons'),
    ]);
    const map = {};
    const order = [];
    for (const a of sessions || []) { map[a.ID] = { a, kind: a.IsDead ? 'dead' : 'session', isBeacon: false }; order.push(a.ID); }
    for (const a of beacons || []) { map[a.ID] = { a, kind: a.IsDead ? 'dead' : 'beacon', isBeacon: true }; order.push(a.ID); }
    STATE.agents = map;
    STATE.order = order;
    renderSidebar();
    renderDashboard();
    renderCount();
    if (STATE.selected && STATE.agents[STATE.selected] && STATE.view === 'agents') {
      renderDetailHeader();
      if (STATE.tab === 'info') renderInfo(); // keep live cadence/last-checkin fresh
    }
    if (STATE.view === 'sliver') fillSvAgents(); // keep the console's agent dropdown fresh
    // Resolve a deep-link (#a/<id>) once the target agent has loaded.
    if (!STATE.selected && location.hash.startsWith('#a/')) applyHash();
  } catch (e) {
    $('#agent-groups').innerHTML = `<div class="side-empty">${esc(e.message)}</div>`;
  }
}

// Agents that the operator has explicitly renamed (persisted). For everyone else
// we default the display label to the machine's hostname rather than the implant
// build/file name (e.g. "beacon.bin"), which is rarely meaningful.
let RENAMED = {};
try { RENAMED = JSON.parse(localStorage.getItem('sliver.renamed')) || {}; } catch { RENAMED = {}; }
function markRenamed(id, renamed) {
  if (renamed) RENAMED[id] = true; else delete RENAMED[id];
  try { localStorage.setItem('sliver.renamed', JSON.stringify(RENAMED)); } catch {}
}
// domainOf extracts the (AD/NetBIOS) domain from the agent's username, which on
// Windows is reported as "DOMAIN\user". Returns '' when there's no domain, or
// when it's just the local machine (workgroup account "HOST\user" or ".\user").
function domainOf(a) {
  const u = a.Username || '';
  const bs = u.indexOf('\\');
  if (bs <= 0) return '';
  const d = u.slice(0, bs);
  if (!d || d === '.' || d.toLowerCase() === (a.Hostname || '').toLowerCase()) return '';
  return d;
}
// hostLabel is the default display label: hostname joined with its domain
// (host.domain) when a domain is known, else just the hostname.
function hostLabel(a) {
  const host = a.Hostname || '';
  const dom = domainOf(a);
  if (host && dom) return host + '.' + dom;
  return host || a.Name || a.ID.slice(0, 8);
}
function agentName(a) {
  if (RENAMED[a.ID] && a.Name) return a.Name;
  return hostLabel(a);
}

// remoteAddr cleans up Sliver's remote-address string. For an HTTP(S) beacon
// behind a redirector that forwards X-Forwarded-For / X-Real-IP, the server
// records "tcp(<socket>)-><real client ip>" — surface the real client IP (with
// the redirector shown as "via"). Anything else is passed through unchanged.
// NOTE: this only reformats what the server already has; when no forwarded-IP
// header is set, the recorded value is the direct socket source and there is no
// public IP to show.
function remoteAddr(a) {
  const r = a.RemoteAddress || '';
  const m = r.match(/^tcp\((.+)\)->(.+)$/);
  return m ? `${m[2]} (via ${m[1]})` : r;
}

function renderCount() {
  const n = STATE.order.filter((id) => STATE.agents[id].kind !== 'dead').length;
  $('#agent-count').textContent = `${n} ${n === 1 ? 'agent' : 'agents'}`;
}

function renderSidebar() {
  const root = $('#agent-groups');
  root.innerHTML = '';
  const groups = { session: [], beacon: [], dead: [] };
  for (const id of STATE.order) {
    const rec = STATE.agents[id];
    const a = rec.a;
    if (STATE.filter) {
      const hay = `${a.Name} ${a.Username} ${a.Hostname} ${a.OS} ${a.RemoteAddress}`.toLowerCase();
      if (!hay.includes(STATE.filter)) continue;
    }
    groups[rec.kind].push(rec);
  }
  const meta = [
    { key: 'session', label: 'sessions' },
    { key: 'beacon', label: 'beacons' },
    { key: 'dead', label: 'dead' },
  ];
  let any = false;
  for (const g of meta) {
    const list = groups[g.key];
    if (g.key === 'dead' && list.length === 0) continue;
    any = any || list.length > 0;
    const wrap = el('div', 'group');
    const head = el('button', 'group-head');
    const open = STATE.groupsOpen[g.key];
    head.innerHTML =
      `<span class="left"><span class="caret">${open ? '▼' : '▶'}</span>` +
      `<span class="dot ${g.key}"></span><span class="label">${g.label}</span></span>` +
      `<span class="count">${list.length}</span>`;
    head.onclick = () => { STATE.groupsOpen[g.key] = !open; renderSidebar(); };
    wrap.appendChild(head);
    if (open) {
      const sorted = list.slice().sort((x, y) => (y.a.LastCheckin || 0) - (x.a.LastCheckin || 0));
      for (const rec of sorted) {
        const a = rec.a;
        const row = el('div', 'agent-row' + (STATE.selected === a.ID ? ' selected' : ''));
        row.innerHTML =
          `<span class="dot sm ${rec.kind}"></span>` +
          `<span class="nm">${esc(agentName(a))}</span>` +
          `<span class="os">${esc(a.OS)}</span>`;
        row.onclick = () => selectAgent(a.ID);
        wrap.appendChild(row);
      }
    }
    root.appendChild(wrap);
  }
  if (!any) {
    root.innerHTML = `<div class="side-empty">${STATE.filter ? 'no matches' : 'no agents connected'}</div>`;
  }
}

function renderDashboard() {
  const stats = $('#dash-stats');
  const sessions = STATE.order.filter((id) => STATE.agents[id].kind === 'session').length;
  const beacons = STATE.order.filter((id) => STATE.agents[id].kind === 'beacon').length;
  const dead = STATE.order.filter((id) => STATE.agents[id].kind === 'dead').length;
  stats.innerHTML = '';
  const tiles = [
    { label: 'sessions', value: sessions, dot: 'session' },
    { label: 'beacons', value: beacons, dot: 'beacon' },
    { label: 'dead', value: dead, dot: 'dead' },
  ];
  for (const t of tiles) {
    const d = el('div', 'stat');
    d.innerHTML =
      `<div class="top"><span class="dot ${t.dot}"></span>${t.label}</div>` +
      `<div class="val">${t.value}</div>`;
    stats.appendChild(d);
  }
  $('#dash-empty').style.display = STATE.order.length === 0 ? 'block' : 'none';
  const deadActions = $('#dash-dead-actions');
  if (dead > 0) {
    deadActions.style.display = 'flex';
    $('#dash-clear-dead').textContent = `kill/remove all dead (${dead})`;
  } else {
    deadActions.style.display = 'none';
    $('#dash-clear-dead-msg').textContent = '';
  }
}

// removeAgentRecord clears one agent's record from the console: a beacon (dead
// or alive) is deleted via RmBeacon; a session has no such "just forget it"
// RPC, so a dead session is cleared via Kill instead — Sliver's Kill handler
// removes the session from its in-memory table unconditionally, even when the
// underlying connection is already gone (the implant-side signal just gets
// dropped silently in that case).
async function removeAgentRecord(id, rec) {
  if (rec.isBeacon) return api('POST', `/api/target/${id}/remove`);
  return api('POST', `/api/target/${id}/kill`);
}
$('#dash-clear-dead').onclick = async () => {
  const deadIds = STATE.order.filter((id) => STATE.agents[id].kind === 'dead');
  if (!deadIds.length) return;
  if (!confirm(`Remove ${deadIds.length} dead agent${deadIds.length === 1 ? '' : 's'} from the console? ` +
    `This does not signal any implant that might still be alive elsewhere.`)) return;
  const msg = $('#dash-clear-dead-msg');
  msg.className = 'muted mono'; msg.textContent = 'removing…';
  let ok = 0, fail = 0;
  for (const id of deadIds) {
    try { await removeAgentRecord(id, STATE.agents[id]); ok++; }
    catch { fail++; }
  }
  msg.className = fail ? 'err' : 'ok';
  msg.textContent = fail ? `removed ${ok}, ${fail} failed` : `removed ${ok}`;
  if (STATE.selected && deadIds.includes(STATE.selected)) { STATE.selected = null; setView('agents'); }
  loadAgents();
};

// =====================================================================
// agent detail
// =====================================================================
function selectAgent(id) {
  STATE.selected = id;
  STATE.tab = 'terminal';
  STATE.cwd = '/';
  renderSidebar();
  renderDetailHeader();
  setView('agents');
  switchTab('terminal');
  renderConsole();
  $('#term-cmd').focus();
  refreshPwd();
}

function renderDetailHeader() {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  const a = rec.a;
  $('#ad-name').textContent = agentName(a);
  const pill = $('#ad-pill');
  pill.className = 'pill ' + rec.kind;
  pill.textContent = rec.kind;
  const meta = $('#ad-meta');
  meta.innerHTML =
    `<span class="hi">${esc(a.Hostname || '—')}</span><span class="sep"> · </span>` +
    `<span>${esc(a.Username)}@${esc(a.OS)}/${esc(a.Arch)}</span><span class="sep"> · </span>` +
    `<span>${esc(remoteAddr(a) || '—')}</span><span class="sep"> · </span>` +
    `<span>${esc(a.Transport)}</span><span class="sep"> · </span>` +
    `<span>last check-in ${ago(a.LastCheckin)}</span>`;
}

$$('#agent-view .tab').forEach((t) => { t.onclick = () => switchTab(t.dataset.tab); });
function switchTab(name) {
  STATE.tab = name;
  if (STATE.selected) {
    const target = '#a/' + STATE.selected + '/' + name;
    if (location.hash !== target) location.hash = target;
  }
  $$('#agent-view .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('#agent-view .tabpane').forEach((p) => p.classList.remove('active'));
  $('#pane-' + name).classList.add('active');
  if (name === 'files') fileRefresh();
  else if (name === 'processes') loadProcs();
  else if (name === 'network') loadNet();
  else if (name === 'pivots') loadPivots();
  else if (name === 'info') renderInfo();
  else if (name === 'terminal') $('#term-cmd').focus();
}

// ----- terminal (Sliver command console for the selected agent) -----
// The terminal interprets *Sliver* commands by default (ls/cd/download/ps/…),
// like the sliver-client prompt. OS shell commands are explicit: `shell <cmd>`
// (aliases `execute`/`run`) or a leading `!`.
const termConsole = makeConsoleInput($('#term-cmd'), TERM_COMMANDS,
  (matches) => STATE.selected && pushConsole(STATE.selected, { cmd: '', out: matches.join('    '), status: 0 }));
$('#term-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('#term-cmd');
  const line = input.value.trim();
  if (!line || !STATE.selected) return;
  input.value = '';
  termConsole.remember(line);
  runTermCommand(STATE.selected, line);
});


// Native Sliver console: sends raw commands to the real sliver-client for
// full command coverage (getsystem, make-token, procdump, hashdump, registry,
// execute-shellcode, armory, profiles, loot, hosts, cat/chmod, pivots, etc.).
async function runTermCommand(id, line) {
  line = line.trim();
  if (!line) return;

  const entry = { cmd: line, out: '', pending: true, status: 0 };
  pushConsole(id, entry);

  // Client-side-only commands.
  const cmd = line.split(/\s+/)[0].toLowerCase();
  if (cmd === 'clear') { STATE.console[id] = []; renderConsole(); return; }
  if (cmd === 'help' || cmd === '?' || cmd === 'h') {
    entry.pending = false;
    entry.out = 'Native Sliver console — type any sliver-client command.\n\n' +
      'Common commands: sessions, beacons, use <id>, info, jobs, listeners, generate,\n' +
      'ls, cd, ps, download, upload, execute, execute-assembly, screenshot, kill,\n' +
      'getsystem, make-token, impersonate, procdump, hashdump, registry,\n' +
      'execute-shellcode, sideload, migrate, armory, profiles, loot, hosts, pivots.\n\n' +
      'Type "help <command>" or "<command> --help" for details.';
    renderConsole();
    return;
  }

  // Send to the native console API.
  try {
    let endpoint;
    if (id) {
      endpoint = `/api/target/${id}/console`;
    } else {
      endpoint = '/api/console';
    }
    const r = await api('POST', endpoint, { cmd: line });
    entry.out = r.output || '(no output)';
    entry.status = 0;
  } catch (err) {
    entry.err = err.message;
    entry.status = 1;
  }
  entry.pending = false;
  renderConsole();
}


function termInfo(id) {
  const a = STATE.agents[id].a;
  return [
    ['id', a.ID], ['name', agentName(a)], ['user', a.Username], ['host', a.Hostname],
    ['os/arch', `${a.OS}/${a.Arch}`], ['transport', a.Transport], ['remote', remoteAddr(a)],
    ['pid', a.PID], ['version', a.Version], ['last check-in', ago(a.LastCheckin)],
  ].map(([k, v]) => `${k.padEnd(14)}${v ?? '—'}`).join('\n');
}
async function termNet(id) {
  const [ifc, ns] = await Promise.all([
    api('GET', `/api/target/${id}/ifconfig`).catch(() => null),
    api('GET', `/api/target/${id}/netstat`).catch(() => null),
  ]);
  let s = '';
  if (ifc && ifc.NetInterfaces) {
    s += '── interfaces ──\n';
    for (const i of ifc.NetInterfaces) s += `${i.Name}  ${(i.IPAddresses || []).join(', ')}\n`;
  }
  if (ns && ns.Entries) {
    s += '\n── connections ──\n';
    for (const e of ns.Entries) s += `${e.Protocol}\t${e.LocalAddr?.Ip}:${e.LocalAddr?.Port}\t${e.RemoteAddr?.Ip}:${e.RemoteAddr?.Port}\t${e.SkState}\n`;
  }
  return s || 'no data';
}
// `upload [dest]` opens a browser file picker and uploads the chosen file to the
// agent (dest dir/path, or the current directory + original name).
function termUpload(id, destArg, entry) {
  const inp = el('input'); inp.type = 'file';
  inp.onchange = async () => {
    const file = inp.files[0];
    if (!file) { Object.assign(entry, { err: 'upload cancelled', status: 1, pending: false }); renderConsole(); return; }
    try {
      const buf = await file.arrayBuffer();
      let bin = ''; const bytes = new Uint8Array(buf);
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      const endsSep = /[\\/]$/.test(destArg);
      const dest = !destArg ? joinPath(STATE.cwd, file.name) : (endsSep ? joinPath(destArg, file.name) : destArg);
      await api('POST', `/api/target/${id}/upload`, { path: dest, data: btoa(bin) });
      Object.assign(entry, { out: `uploaded ${file.name} → ${dest}`, pending: false });
    } catch (e) { Object.assign(entry, { err: e.message, status: 1, pending: false }); }
    renderConsole();
  };
  inp.click();
}

function applyExecResult(entry, r) {
  entry.pending = false;
  entry.queued = false;
  entry.status = r.status;
  entry.out = (r.stdout || '').replace(/\s+$/, '');
  entry.err = (r.stderr || '').replace(/\s+$/, '');
  // Like a real shell: a command with no output just shows a blank line. Only
  // surface an exit-code marker when a command failed with nothing printed.
  if (!entry.out && !entry.err && r.status) entry.err = `[exit ${r.status}]`;
}

// pollBeaconTask waits for an async beacon task result. Beacons only report
// back on their own schedule, so we poll the task endpoint until it completes
// (or give up after a generous window). The console row shows the queued state
// meanwhile so the operator knows the command is in flight, not lost.
async function pollBeaconTask(id, taskId, entry) {
  const started = Date.now();
  const maxMs = 30 * 60 * 1000;
  while (Date.now() - started < maxMs) {
    await sleep(3000);
    let r;
    try {
      r = await api('GET', `/api/target/${id}/task/${taskId}`);
    } catch (err) {
      continue; // transient — keep waiting for the next check-in
    }
    if (r.done) { applyExecResult(entry, r); renderConsole(); return; }
    if (entry.state !== r.state) { entry.state = r.state; renderConsole(); }
  }
  entry.pending = false; entry.queued = false;
  entry.err = 'timed out waiting for beacon result'; entry.status = 1;
  renderConsole();
}

function pushConsole(id, entry) {
  entry.ts = Date.now();
  (STATE.console[id] = STATE.console[id] || []).push(entry);
  renderConsole();
}

function renderConsole() {
  const scroll = $('#term-scroll');
  const atBottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 80;
  const log = STATE.console[STATE.selected] || [];
  scroll.innerHTML = '';
  if (log.length === 0) {
    scroll.appendChild(el('p', 'muted mono', 'No commands yet. Type one below.'));
  }
  for (const entry of log) {
    const row = el('div', 'cmd-row');
    const line = el('div', 'cmd-line');
    const status = entry.pending
      ? (entry.queued
          ? (entry.state === 'sent' ? 'sent · awaiting result' : 'queued · awaiting check-in')
          : 'running…')
      : '';
    line.innerHTML =
      `<span class="dollar">$</span>` +
      `<span class="txt">${esc(entry.cmd)}</span>` +
      (status ? `<span class="queued">${status}</span>` : '');
    row.appendChild(line);
    // Output rendered inline, always visible — a plain terminal transcript.
    if (entry.out) {
      const pre = el('pre', 'cmd-out');
      pre.textContent = entry.out;
      row.appendChild(pre);
    }
    if (entry.err) {
      const pre = el('pre', 'cmd-out err');
      pre.textContent = entry.err;
      row.appendChild(pre);
    }
    if (entry.img) {
      const img = el('img');
      img.src = `data:image/png;base64,${entry.img}`;
      img.style.maxWidth = '100%'; img.style.borderRadius = '6px'; img.style.margin = '4px 0 10px';
      row.appendChild(img);
    }
    scroll.appendChild(row);
  }
  if (atBottom) scroll.scrollTop = scroll.scrollHeight;
}

async function refreshPwd() {
  try { const r = await api('GET', `/api/target/${STATE.selected}/pwd`); STATE.cwd = r.Path; } catch {}
}

// ----- files -----
$('#files-up').onclick = () => listDir(parentPath(STATE.cwd));
$('#files-refresh').onclick = () => fileRefresh();
$('#files-mkdir').onclick = async () => {
  const name = prompt('New directory name:');
  if (!name) return;
  try { await api('POST', `/api/target/${STATE.selected}/mkdir`, { path: joinPath(STATE.cwd, name) }); fileRefresh(); }
  catch (e) { alert(e.message); }
};
$('#files-upload').addEventListener('change', async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  const buf = await file.arrayBuffer();
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  try {
    await api('POST', `/api/target/${STATE.selected}/upload`, { path: joinPath(STATE.cwd, file.name), data: btoa(bin) });
    fileRefresh();
  } catch (e) { alert(e.message); }
  ev.target.value = '';
});

function fileRefresh() { listDir(STATE.cwd); }
async function listDir(path) {
  const list = $('#files-list');
  list.innerHTML = '<div class="side-empty">loading…</div>';
  try {
    const r = await api('POST', `/api/target/${STATE.selected}/ls`, { path });
    STATE.cwd = r.Path || path;
    $('#files-path').value = STATE.cwd;
    list.innerHTML = '';
    const files = (r.Files || []).filter((f) => f.Name !== '.')
      .sort((a, b) => (b.IsDir - a.IsDir) || a.Name.localeCompare(b.Name));
    if (files.length === 0) { list.innerHTML = '<div class="side-empty">empty directory</div>'; return; }
    for (const f of files) {
      const row = el('div', 'file-row');
      const nm = el('span', 'fn ' + (f.IsDir ? 'dir' : 'file'), (f.IsDir ? '📁 ' : '📄 ') + f.Name);
      const full = joinPath(STATE.cwd, f.Name);
      nm.onclick = f.IsDir ? () => listDir(full) : () => downloadFile(full, f.Name);
      row.appendChild(nm);
      row.appendChild(el('span', 'sz', f.IsDir ? '' : fmtSize(f.Size)));
      row.appendChild(el('span', 'md', f.Mode || ''));
      const acts = el('span', 'acts');
      if (!f.IsDir) {
        const dl = el('button', 'btn ghost sm', '⬇');
        dl.onclick = (e) => { e.stopPropagation(); downloadFile(full, f.Name); };
        acts.appendChild(dl);
      }
      const rm = el('button', 'btn ghost sm', '🗑');
      rm.onclick = (e) => { e.stopPropagation(); rmFile(full, f.IsDir); };
      acts.appendChild(rm);
      row.appendChild(acts);
      list.appendChild(row);
    }
  } catch (e) {
    list.innerHTML = `<div class="side-empty">${esc(e.message)}</div>`;
  }
}
async function downloadFile(path, name) {
  try {
    const r = await api('POST', `/api/target/${STATE.selected}/download`, { path });
    if (!r.exists) { alert('file not found'); return; }
    saveBlob(b64ToBlob(r.data), name);
  } catch (e) { alert(e.message); }
}
async function rmFile(path, isDir) {
  if (!confirm('Delete ' + path + '?')) return;
  try { await api('POST', `/api/target/${STATE.selected}/rm`, { path, recursive: isDir }); fileRefresh(); }
  catch (e) { alert(e.message); }
}

// ----- processes -----
async function loadProcs() {
  const body = $('#procs-body');
  body.innerHTML = '<tr><td colspan="5" class="empty">loading…</td></tr>';
  try {
    const r = await api('GET', `/api/target/${STATE.selected}/ps`);
    body.innerHTML = '';
    const procs = (r.Processes || []).slice().sort((a, b) => a.Pid - b.Pid);
    if (procs.length === 0) { body.innerHTML = '<tr><td colspan="5" class="empty">no processes</td></tr>'; return; }
    for (const p of procs) {
      const tr = el('tr');
      tr.innerHTML =
        `<td>${p.Pid}</td><td>${p.Ppid}</td><td>${esc(p.Owner)}</td>` +
        `<td>${esc(p.Architecture)}</td><td>${esc(p.Executable)}</td>`;
      body.appendChild(tr);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="5" class="empty">${esc(e.message)}</td></tr>`; }
}

// ----- network -----
async function loadNet() {
  const out = $('#net-out');
  out.textContent = 'loading…';
  try {
    const [ifc, ns] = await Promise.all([
      api('GET', `/api/target/${STATE.selected}/ifconfig`).catch(() => null),
      api('GET', `/api/target/${STATE.selected}/netstat`).catch(() => null),
    ]);
    let s = '';
    if (ifc && ifc.NetInterfaces) {
      s += '── Interfaces ──\n';
      for (const i of ifc.NetInterfaces) s += `${i.Name}  ${(i.IPAddresses || []).join(', ')}\n`;
    }
    if (ns && ns.Entries) {
      s += '\n── Connections ──\n';
      for (const e of ns.Entries) {
        s += `${e.Protocol}\t${e.LocalAddr?.Ip}:${e.LocalAddr?.Port}\t` +
             `${e.RemoteAddr?.Ip}:${e.RemoteAddr?.Port}\t${e.SkState}\n`;
      }
    }
    out.textContent = s || 'no data';
  } catch (e) { out.textContent = e.message; }
}

// ----- screenshot -----
$('#shot-capture').onclick = async () => {
  const wrap = $('#shot-img');
  wrap.textContent = 'capturing…';
  try {
    const r = await api('GET', `/api/target/${STATE.selected}/screenshot`);
    if (!r.data) { wrap.textContent = 'no image data'; return; }
    wrap.innerHTML = `<img src="data:image/png;base64,${r.data}">`;
  } catch (e) { wrap.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
};

// ----- pivots (per-session) -----
async function loadPivots() {
  if (!STATE.selected) return;
  const body = $('#pivot-body');
  body.innerHTML = '<tr><td colspan="5" class="muted">loading…</td></tr>';
  try {
    const pivots = await api('GET', `/api/target/${STATE.selected}/pivots`);
    if (!pivots || pivots.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">no active pivot listeners</td></tr>';
      return;
    }
    body.innerHTML = '';
    for (const p of pivots) {
      const row = el('tr');
      row.innerHTML =
        `<td class="mono">${p.ID}</td>` +
        `<td>${p.Type === 0 ? 'TCP' : p.Type === 2 ? 'Named Pipe' : 'UDP'}</td>` +
        `<td class="mono">${p.BindAddress || '—'}</td>` +
        `<td>${(p.Pivots || []).length} downstream</td>` +
        `<td><button class="btn danger xs" onclick="stopPivot('${STATE.selected}', ${p.ID})">stop</button></td>`;
      body.appendChild(row);
    }
  } catch (e) {
    body.innerHTML = `<tr><td colspan="5" class="err">${esc(e.message)}</td></tr>`;
  }
}
async function stopPivot(sessionId, pivotId) {
  if (!confirm(`Stop pivot ${pivotId}?`)) return;
  try {
    await api('DELETE', `/api/target/${sessionId}/pivots/${pivotId}`);
    loadPivots();
  } catch (e) { alert(e.message); }
}
$('#pivot-start').onclick = async () => {
  const type = $('#pivot-type').value;
  const bind = ($('#pivot-bind').value || '').trim();
  if (!bind && type === 'tcp') {
    alert('TCP: specify bind address (e.g. 0.0.0.0:9898)');
    return;
  }
  const msg = $('#pivot-msg');
  msg.textContent = 'starting…';
  try {
    await api('POST', `/api/target/${STATE.selected}/pivots`, { type, bind });
    msg.textContent = 'started';
    $('#pivot-bind').value = '';
    setTimeout(() => { msg.textContent = ''; loadPivots(); }, 1000);
  } catch (e) { msg.textContent = 'error: ' + e.message; }
};

// ----- info -----
let infoShownId = null; // which agent the info pane's name field is populated for
function renderInfo() {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  const a = rec.a;
  const rows = [
    ['type', rec.kind],
    ['agent id', a.ID, true],
    ['name', a.Name],
    ['user', a.Username],
    ['hostname', a.Hostname],
    ['domain', domainOf(a)],
    ['os / arch', `${a.OS}/${a.Arch}`],
    ['remote address', remoteAddr(a), true],
    ['transport', a.Transport],
    ['pid', a.PID],
    ['version', a.Version],
    ['last check-in', ago(a.LastCheckin)],
  ];
  const dl = $('#info-dl');
  dl.innerHTML = '';
  for (const [k, v, mono] of rows) {
    const div = el('div');
    div.appendChild(el('dt', null, k));
    div.appendChild(el('dd', mono ? 'mono' : null, v == null || v === '' ? '—' : String(v)));
    dl.appendChild(div);
  }
  $('#info-kill-msg').textContent = '';

  // Name: populate only when the shown agent changes, so a background refresh
  // (every 5s) doesn't clobber what the operator is typing or wipe a status msg.
  if (infoShownId !== a.ID) {
    infoShownId = a.ID;
    $('#info-name').value = RENAMED[a.ID] ? (a.Name || '') : '';
    $('#info-rename-msg').textContent = '';
  }
  $('#info-name').placeholder = hostLabel(a);
  $('#info-rename-reset').style.display = RENAMED[a.ID] ? '' : 'none';

  // "Remove from console" (RmBeacon) applies to beacons — including dead ones
  // that will never check in for the kill to auto-remove them.
  const removable = rec.kind === 'beacon' || rec.kind === 'dead';
  $('#info-remove').style.display = removable ? '' : 'none';
  $('#info-remove-note').style.display = removable ? '' : 'none';

  // Beacon cadence editor: sleep + jitter, live-reconfigurable. Beacon proto
  // Interval/Jitter are nanoseconds; show and edit in seconds.
  const cad = $('#info-cadence');
  if (rec.kind === 'beacon') {
    const secs = (ns) => Math.max(0, Math.round((ns || 0) / 1e9));
    const iv = secs(a.Interval);
    const jt = secs(a.Jitter);
    $('#cadence-interval').value = iv;
    $('#cadence-jitter').value = jt;
    $('#cadence-current').innerHTML =
      `Currently <span class="hi">${iv}s</span> sleep, <span class="hi">${jt}s</span> jitter` +
      ` &middot; next check-in in ${iv}&ndash;${iv + jt}s.`;
    $('#cadence-msg').textContent = '';
    cad.style.display = '';
  } else {
    cad.style.display = 'none';
  }
}
$('#cadence-save').onclick = async () => {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  const interval = parseInt($('#cadence-interval').value, 10);
  const jitter = parseInt($('#cadence-jitter').value, 10);
  const msg = $('#cadence-msg');
  if (!(interval >= 1)) { msg.className = 'err'; msg.textContent = 'sleep must be ≥ 1s'; return; }
  if (!(jitter >= 0)) { msg.className = 'err'; msg.textContent = 'jitter must be ≥ 0s'; return; }
  msg.className = 'muted mono'; msg.textContent = 'saving…';
  try {
    await api('POST', `/api/target/${STATE.selected}/reconfigure`, { interval, jitter });
    msg.className = 'ok'; msg.textContent = 'saved — applies on next check-in';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
};
$('#info-kill').onclick = async () => {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  if (!confirm(`Kill agent ${agentName(rec.a)}?`)) return;
  const msg = $('#info-kill-msg');
  msg.className = 'muted mono'; msg.textContent = ' killing…';
  try {
    await api('POST', `/api/target/${STATE.selected}/kill`);
    msg.className = 'ok'; msg.textContent = ' killed';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
};
$('#info-rename').onclick = async () => {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  const id = STATE.selected;
  const msg = $('#info-rename-msg');
  const name = $('#info-name').value.trim();
  if (!name) { msg.className = 'err'; msg.textContent = ' enter a name (or use reset)'; return; }
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(name) || /^\.\.?/.test(name)) {
    msg.className = 'err'; msg.textContent = ' letters, digits, .-_ only (max 32)'; return;
  }
  msg.className = 'muted mono'; msg.textContent = ' renaming…';
  try {
    await api('POST', `/api/target/${id}/rename`, { name });
    markRenamed(id, true);
    msg.className = 'ok'; msg.textContent = ' renamed';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
};
$('#info-rename-reset').onclick = async () => {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  const id = STATE.selected;
  const host = rec.a.Hostname;
  const msg = $('#info-rename-msg');
  // Revert the display label to the hostname default. If the hostname is a valid
  // Sliver name, also push it server-side so the two stay in sync; otherwise just
  // drop the local override and fall back to hostname for display.
  const validHost = host && /^[A-Za-z0-9._-]{1,32}$/.test(host) && !/^\.\.?/.test(host);
  msg.className = 'muted mono'; msg.textContent = ' resetting…';
  try {
    if (validHost) await api('POST', `/api/target/${id}/rename`, { name: host });
    markRenamed(id, false);
    $('#info-name').value = '';
    msg.className = 'ok'; msg.textContent = ' reset to hostname';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
};
$('#info-remove').onclick = async () => {
  const rec = STATE.agents[STATE.selected];
  if (!rec) return;
  if (!confirm(`Remove ${agentName(rec.a)} from the console? (does not signal the implant)`)) return;
  const id = STATE.selected;
  const msg = $('#info-kill-msg');
  msg.className = 'muted mono'; msg.textContent = ' removing…';
  try {
    await removeAgentRecord(id, rec);
    msg.className = 'ok'; msg.textContent = ' removed';
    if (STATE.selected === id) { STATE.selected = null; setView('agents'); }
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
};

// =====================================================================
// listeners
// =====================================================================
// Bind-host guard. VPN/tunnel devices (tun/tap/wg/ppp/…) are created late — often
// well after sliver.service starts at boot — so a listener persisted against one
// of their IPs fails to restore with "cannot assign requested address". Sliver
// leaves the DB record behind when that happens, and PortInUse() matches on the
// PORT ALONE (ignoring both bind host and protocol), so the stranded record then
// blocks that port for every listener until the record is cleared. Binding
// 0.0.0.0 covers the VPN interface anyway, with none of that fragility.
const VPN_IFACE = /^(tun|tap|wg|ppp|utun|ligolo)/i;
function ifaceForIP(ip) {
  const i = STATE.interfaces.find((x) => x.ip === ip);
  return i ? i.name : '';
}
function isVPNBind(ip) {
  return !!ip && ip !== '0.0.0.0' && VPN_IFACE.test(ifaceForIP(ip));
}
function updateBindWarning() {
  const note = $('#lst-host-warn');
  const ip = $('#lst-host').value;
  if (!isVPNBind(ip)) { note.style.display = 'none'; return; }
  const iface = ifaceForIP(ip);
  note.style.display = '';
  note.innerHTML =
    `<b>${esc(iface)}</b> is a VPN/tunnel interface. It may not exist yet when the Sliver ` +
    `server starts at boot, so a listener bound to <b>${esc(ip)}</b> will fail to restore and ` +
    `its leftover record will reserve this port for <i>every</i> protocol until you clear it. ` +
    `Prefer <b>0.0.0.0</b> — it already covers ${esc(iface)}.`;
}
$('#lst-host').addEventListener('change', updateBindWarning);

$('#lst-start').onclick = startListener;
async function startListener() {
  const type = $('#lst-type').value;
  const host = $('#lst-host').value.trim();
  const port = parseInt($('#lst-port').value, 10) || 0;
  const domain = $('#lst-domain').value.trim();
  const msg = $('#lst-msg');
  if (isVPNBind(host)) {
    const ok = confirm(
      `Bind to ${host} (${ifaceForIP(host)})?\n\n` +
      `This is a VPN/tunnel interface that may not exist at boot, so this listener will ` +
      `fail to restore and will strand port ${port || '(default)'} until the leftover record ` +
      `is removed.\n\n0.0.0.0 already covers ${ifaceForIP(host)}.\n\nBind to ${host} anyway?`);
    if (!ok) return;
  }
  msg.className = 'muted mono'; msg.textContent = 'starting…';
  try {
    if (type === 'mtls') await api('POST', '/api/jobs/mtls', { host, port });
    else await api('POST', '/api/jobs/http', { host, domain, port, secure: type === 'https' });
    msg.className = 'ok'; msg.textContent = 'started';
    loadJobs();
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
}
async function loadJobs() {
  const body = $('#jobs-body');
  try {
    const jobs = await api('GET', '/api/jobs');
    body.innerHTML = '';
    if (!jobs || !jobs.length) { body.innerHTML = '<tr><td colspan="6" class="empty">no active listeners</td></tr>'; return; }
    for (const j of jobs) {
      const tr = el('tr');
      tr.innerHTML =
        `<td>${j.ID}</td><td>${esc(j.Name)}</td><td>${esc(j.Protocol)}</td>` +
        `<td>${j.Port}</td><td>${esc(j.Description)}</td><td></td>`;
      const stop = el('button', 'btn danger sm', 'stop');
      stop.onclick = () => killJob(j.ID);
      tr.lastElementChild.appendChild(stop);
      body.appendChild(tr);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="6" class="empty">${esc(e.message)}</td></tr>`; }
  loadStale();
}
async function killJob(id) {
  try { await api('DELETE', '/api/jobs/' + id); loadJobs(); } catch (e) { alert(e.message); }
}
// Stranded listener records in the Sliver DB — see the note in the Listeners
// view. Detection reads the server DB directly, so it can surface (and clear)
// records the operator gRPC API can't reach.
async function loadStale() {
  const section = $('#stale-section');
  const body = $('#stale-body');
  let stale;
  try {
    stale = await api('GET', '/api/jobs/stale');
  } catch (e) {
    // Detection unavailable (DB not found / not co-located): stay quiet rather
    // than nag on every poll.
    section.style.display = 'none';
    return;
  }
  if (!stale || !stale.length) { section.style.display = 'none'; return; }
  section.style.display = '';
  $('#stale-count').textContent = stale.length;
  body.innerHTML = '';
  for (const s of stale) {
    const tr = el('tr');
    tr.innerHTML =
      `<td>${s.job_id}</td><td>${esc(s.type)}</td>` +
      `<td class="mono">${esc(s.host || '—')}</td><td>${s.port}</td><td></td>`;
    const rm = el('button', 'btn danger sm', 'remove');
    rm.onclick = () => removeStale(s.job_id, `${s.type} ${s.host}:${s.port}`);
    tr.lastElementChild.appendChild(rm);
    body.appendChild(tr);
  }
}
async function removeStale(id, label) {
  if (!confirm(`Remove stale listener record (job ${id}: ${label}) from the Sliver DB?`)) return;
  try { await api('DELETE', '/api/jobs/stale/' + id); loadJobs(); } catch (e) { alert(e.message); }
}

// =====================================================================
// pivots (main view: server-wide pivot graph)
// =====================================================================
async function loadPivotGraph() {
  const body = $('#pivot-graph-body');
  body.innerHTML = '<tr><td colspan="3" class="muted">loading…</td></tr>';
  try {
    const graph = await api('GET', '/api/pivots');
    if (!graph || !graph.Children || graph.Children.length === 0) {
      body.innerHTML = '<tr><td colspan="3" class="muted">no pivots established</td></tr>';
      return;
    }
    body.innerHTML = '';
    for (const child of graph.Children) {
      const row = el('tr');
      const pivotCount = (child.Children || []).length;
      row.innerHTML =
        `<td class="mono">${child.ID || '—'}</td>` +
        `<td>${child.Hostname || '—'}</td>` +
        `<td>${pivotCount}</td>`;
      body.appendChild(row);
    }
  } catch (e) {
    body.innerHTML = `<tr><td colspan="3" class="err">${esc(e.message)}</td></tr>`;
  }
}

// =====================================================================
// generate
// =====================================================================
// Keep the cadence section (sleep/jitter/etc.) always visible so the option is
// discoverable; just note that sleep & jitter only apply to beacon builds.
function updateGenType() {
  const beacon = $('#gen-type').value === 'beacon';
  $('#gen-session-note').style.display = beacon ? 'none' : '';
}
$('#gen-type').addEventListener('change', updateGenType);
$('#gen-beacon-section').style.display = '';
updateGenType();
$('#gen-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const st = $('#gen-status');
  const c2 = readC2Fields('gen');
  const opts = {
    OS: $('#gen-os').value,
    Arch: $('#gen-arch').value,
    Format: $('#gen-format').value,
    IsBeacon: $('#gen-type').value === 'beacon',
    Interval: parseInt($('#gen-interval').value, 10) || 60,
    Jitter: parseInt($('#gen-jitter').value, 10) || 0,
    Reconnect: parseInt($('#gen-reconnect').value, 10) || 60,
    MaxErrors: parseInt($('#gen-max-errors').value, 10) || 1000,
    Poll: parseInt($('#gen-poll').value, 10) || 360,
    Name: $('#gen-name').value.trim(),
    SaveDir: $('#gen-savedir').value.trim(),
    ...c2,
  };
  if (!opts.C2Host) {
    st.className = 'err'; st.textContent = c2.C2Type === 'named-pipe' ? 'enter a pipe path' : 'select a C2 host';
    return;
  }
  if (opts.C2Type !== 'named-pipe' && !opts.C2Port) {
    st.className = 'err'; st.textContent = 'specify a C2 port';
    return;
  }
  if (!opts.SaveDir) {
    st.className = 'err'; st.textContent = 'specify a save directory — the implant is written to disk, not downloaded';
    return;
  }
  const btn = $('#gen-btn');
  btn.disabled = true;
  st.className = 'muted mono'; st.textContent = 'building… (this can take a minute or two)';
  try {
    const r = await api('POST', '/api/generate', opts);
    st.className = 'ok';
    st.textContent = `built ${r.name} (${fmtSize(r.size)}) — saved to ${r.savedPath}`;
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
  finally { btn.disabled = false; }
});

// =====================================================================
// directory browser (bridge host filesystem — e.g. Generate's save dir)
// =====================================================================
// A small reusable modal: browse subdirectories on the bridge host and write
// the chosen path into a target <input>. There's no browser API for picking a
// directory on a *remote* server, so this drives GET /api/browse-dirs instead.
const DIRB = { targetInput: null };
function openDirBrowser(targetInput) {
  DIRB.targetInput = targetInput;
  $('#dirbrowser').style.display = 'flex';
  loadDirBrowser(targetInput.value.trim());
}
function closeDirBrowser() {
  $('#dirbrowser').style.display = 'none';
  DIRB.targetInput = null;
}
async function loadDirBrowser(path) {
  const list = $('#dirbrowser-list');
  const msg = $('#dirbrowser-msg');
  list.innerHTML = '<div class="side-empty">loading…</div>';
  msg.textContent = '';
  try {
    const r = await api('GET', '/api/browse-dirs' + (path ? '?path=' + encodeURIComponent(path) : ''));
    $('#dirbrowser-path').textContent = r.path;
    $('#dirbrowser-up').disabled = !r.parent;
    DIRB.current = r.path;
    DIRB.parent = r.parent;
    list.innerHTML = '';
    if (!r.dirs || !r.dirs.length) {
      list.innerHTML = '<div class="side-empty">no subdirectories</div>';
      return;
    }
    for (const d of r.dirs) {
      const row = el('div', 'file-row');
      const nm = el('span', 'fn dir', '📁 ' + d.name);
      nm.onclick = () => loadDirBrowser(d.path);
      row.appendChild(nm);
      list.appendChild(row);
    }
  } catch (e) {
    msg.textContent = e.message;
    list.innerHTML = '';
  }
}
$('#gen-savedir-browse').onclick = () => openDirBrowser($('#gen-savedir'));
$('#dirbrowser-close').onclick = closeDirBrowser;
$('#dirbrowser-up').onclick = () => { if (DIRB.parent) loadDirBrowser(DIRB.parent); };
$('#dirbrowser-select').onclick = () => {
  if (DIRB.targetInput && DIRB.current) DIRB.targetInput.value = DIRB.current;
  closeDirBrowser();
};
$('#dirbrowser').addEventListener('click', (e) => { if (e.target.id === 'dirbrowser') closeDirBrowser(); });

// =====================================================================
// C2 type helpers shared by Generate / Profiles forms (named-pipe toggle)
// =====================================================================
const OUTPUT_FORMAT_NAME = { 0: 'shared', 1: 'shellcode', 2: 'exe', 3: 'service' };
function fmtC2(cfg) {
  if (!cfg) return '—';
  const urls = (cfg.C2 || []).map((c) => c.URL);
  return urls.length ? urls.join(', ') : '—';
}
// Toggle a Type=C2Type form between host+port fields (mtls/http/https) and a
// single pipe-path field (named-pipe). `prefix` is 'gen' or 'prof'.
function updateC2Fields(prefix) {
  const isPipe = $(`#${prefix}-c2-type`).value === 'named-pipe';
  $(`#${prefix}-c2-host-field`).style.display = isPipe ? 'none' : '';
  $(`#${prefix}-c2-port-field`).style.display = isPipe ? 'none' : '';
  $(`#${prefix}-c2-pipe-field`).style.display = isPipe ? '' : 'none';
  const note = $(`#${prefix}-c2-note`);
  if (note) {
    note.textContent = isPipe
      ? 'Dials a named-pipe pivot listener already running on a session (see its Pivots tab).'
      : 'Match this to a running listener.';
  }
}
$('#gen-c2-type').addEventListener('change', () => updateC2Fields('gen'));
$('#prof-c2-type').addEventListener('change', () => updateC2Fields('prof'));
updateC2Fields('gen');
updateC2Fields('prof');
// Read a form's C2 fields into { C2Type, C2Host, C2Port } — C2Host doubles as
// the pipe path when C2Type is named-pipe.
function readC2Fields(prefix) {
  const type = $(`#${prefix}-c2-type`).value;
  if (type === 'named-pipe') {
    return { C2Type: type, C2Host: $(`#${prefix}-c2-pipe`).value.trim(), C2Port: 0 };
  }
  return {
    C2Type: type,
    C2Host: $(`#${prefix}-c2-host`).value.trim(),
    C2Port: parseInt($(`#${prefix}-c2-port`).value, 10) || 0,
  };
}

// =====================================================================
// implant profiles (saved generate configs)
// =====================================================================
function updateProfType() {
  const beacon = $('#prof-type').value === 'beacon';
  $('#prof-session-note').style.display = beacon ? 'none' : '';
}
$('#prof-type').addEventListener('change', updateProfType);
updateProfType();

$('#prof-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const st = $('#prof-status');
  const name = $('#prof-name').value.trim();
  if (!name) { st.className = 'err'; st.textContent = 'enter a profile name'; return; }
  const c2 = readC2Fields('prof');
  if (!c2.C2Host) { st.className = 'err'; st.textContent = c2.C2Type === 'named-pipe' ? 'enter a pipe path' : 'select a C2 host'; return; }
  if (c2.C2Type !== 'named-pipe' && !c2.C2Port) { st.className = 'err'; st.textContent = 'specify a C2 port'; return; }
  const opts = {
    Name: name,
    OS: $('#prof-os').value,
    Arch: $('#prof-arch').value,
    Format: $('#prof-format').value,
    IsBeacon: $('#prof-type').value === 'beacon',
    Interval: parseInt($('#prof-interval').value, 10) || 60,
    Jitter: parseInt($('#prof-jitter').value, 10) || 0,
    Reconnect: parseInt($('#prof-reconnect').value, 10) || 60,
    MaxErrors: parseInt($('#prof-max-errors').value, 10) || 1000,
    Poll: parseInt($('#prof-poll').value, 10) || 360,
    ...c2,
  };
  const btn = $('#prof-btn');
  btn.disabled = true;
  st.className = 'muted mono'; st.textContent = 'saving…';
  try {
    await api('POST', '/api/profiles', opts);
    st.className = 'ok'; st.textContent = `saved profile "${name}"`;
    loadProfiles();
  } catch (e) { st.className = 'err'; st.textContent = e.message; }
  finally { btn.disabled = false; }
});

async function loadProfiles() {
  const body = $('#profiles-body');
  body.innerHTML = '<tr><td colspan="6" class="muted">loading…</td></tr>';
  try {
    const profiles = await api('GET', '/api/profiles');
    if (!profiles || !profiles.length) {
      body.innerHTML = '<tr><td colspan="6" class="muted">no saved profiles</td></tr>';
      loadStagerProfiles();
      return;
    }
    body.innerHTML = '';
    for (const p of profiles) {
      const cfg = p.Config || {};
      const tr = el('tr');
      tr.innerHTML =
        `<td class="mono">${esc(p.Name)}</td>` +
        `<td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td>` +
        `<td>${esc(OUTPUT_FORMAT_NAME[cfg.Format] ?? cfg.Format)}</td>` +
        `<td>${cfg.IsBeacon ? 'beacon' : 'session'}</td>` +
        `<td class="mono" style="font-size:12px">${esc(fmtC2(cfg))}</td>` +
        `<td></td>`;
      const rm = el('button', 'btn danger sm', 'delete');
      rm.onclick = () => deleteProfile(p.Name);
      tr.lastElementChild.appendChild(rm);
      body.appendChild(tr);
    }
  } catch (e) {
    body.innerHTML = `<tr><td colspan="6" class="err">${esc(e.message)}</td></tr>`;
  }
  loadStagerProfiles();
}
async function deleteProfile(name) {
  if (!confirm(`Delete profile "${name}"?`)) return;
  try { await api('DELETE', '/api/profiles/' + encodeURIComponent(name)); loadProfiles(); }
  catch (e) { alert(e.message); }
}

// ----- stage listener (Listeners tab: generate + serve a profile's stager) -----
async function loadStagerProfiles() {
  const sel = $('#stager-profile');
  if (!sel) return;
  const prev = sel.value;
  try {
    const profiles = await api('GET', '/api/profiles');
    sel.innerHTML = '';
    if (!profiles || !profiles.length) {
      sel.appendChild(new Option('— no saved profiles —', ''));
    } else {
      for (const p of profiles) sel.appendChild(new Option(p.Name, p.Name));
    }
    if (prev && Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
  } catch { sel.innerHTML = ''; sel.appendChild(new Option('— failed to load profiles —', '')); }
}
$('#stager-start').onclick = async () => {
  const profile = $('#stager-profile').value;
  const host = $('#stager-host').value.trim();
  const port = parseInt($('#stager-port').value, 10) || 0;
  const compress = $('#stager-compress').value;
  const aesKey = $('#stager-aes-key').value.trim();
  const rc4Key = $('#stager-rc4-key').value.trim();
  const msg = $('#stager-msg');
  if (!profile) { msg.className = 'err'; msg.textContent = 'select a profile'; return; }
  if (!port) { msg.className = 'err'; msg.textContent = 'enter a port'; return; }
  if (aesKey && rc4Key) { msg.className = 'err'; msg.textContent = 'use AES or RC4, not both'; return; }
  msg.className = 'muted mono'; msg.textContent = 'building & starting… (this can take a minute)';
  try {
    await api('POST', '/api/stagers', { host, port, profile, compress, aesKey, rc4Key });
    msg.className = 'ok'; msg.textContent = 'started';
    loadJobs();
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
};

// =====================================================================
// implants (previously generated builds)
// =====================================================================
async function loadImplants() {
  const body = $('#implants-body');
  body.innerHTML = '<tr><td colspan="7" class="muted">loading…</td></tr>';
  try {
    const builds = await api('GET', '/api/implants');
    if (!builds || !builds.length) {
      body.innerHTML = '<tr><td colspan="7" class="muted">no implants built yet</td></tr>';
      return;
    }
    body.innerHTML = '';
    for (const b of builds) {
      const cfg = b.Config || {};
      const tr = el('tr');
      tr.innerHTML =
        `<td class="mono">${esc(b.Name)}</td>` +
        `<td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td>` +
        `<td>${esc(OUTPUT_FORMAT_NAME[cfg.Format] ?? cfg.Format)}</td>` +
        `<td>${cfg.IsBeacon ? 'beacon' : 'session'}</td>` +
        `<td class="mono" style="font-size:12px">${esc(fmtC2(cfg))}</td>` +
        `<td>${b.Staged ? 'yes' : 'no'}</td>` +
        `<td></td>`;
      const rm = el('button', 'btn danger sm', 'delete');
      rm.onclick = () => deleteImplant(b.Name);
      tr.lastElementChild.appendChild(rm);
      body.appendChild(tr);
    }
  } catch (e) {
    body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`;
  }
}
async function deleteImplant(name) {
  if (!confirm(`Delete implant "${name}"? This removes its build record/artifact from the server.`)) return;
  try { await api('DELETE', '/api/implants/' + encodeURIComponent(name)); loadImplants(); }
  catch (e) { alert(e.message); }
}

// =====================================================================
// Sliver console (bridge-backed command console)
// =====================================================================
// A sliver-client-style console that dispatches to the bridge's gRPC-backed
// REST API. Server-level commands (sessions/beacons/jobs) plus, after `use`,
// per-agent commands (info/ls/ps/netstat/execute/…). The agent dropdown is a
// shortcut for `use <id>`.
const SV = { current: null, booted: false };

function loadSliver() {
  fillSvAgents();
  if (!SV.booted) { SV.booted = true; svWelcome(); }
  $('#sv-cmd').focus();
}

function fillSvAgents() {
  const sel = $('#sv-agent');
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = '';
  sel.appendChild(new Option('— select agent —', ''));
  for (const id of STATE.order) {
    const rec = STATE.agents[id];
    if (rec.kind === 'dead') continue;
    sel.appendChild(new Option(`${agentName(rec.a)} · ${rec.kind} · ${rec.a.OS}`, id));
  }
  if (SV.current && STATE.agents[SV.current]) sel.value = SV.current;
  else if (prev && Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
}

function svScroll() { return $('#sv-scroll'); }
function svPrint(cls, text) {
  const scroll = svScroll();
  const atBottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 80;
  const div = el('div', 'sv-line ' + cls);
  div.textContent = text;
  scroll.appendChild(div);
  if (atBottom) scroll.scrollTop = scroll.scrollHeight;
  return div;
}
function svEcho(line) {
  const scroll = svScroll();
  const div = el('div', 'sv-line cmd');
  const prompt = SV.current ? `sliver (${agentName(STATE.agents[SV.current].a)}) >` : 'sliver >';
  div.innerHTML = `<span class="p">${esc(prompt)}</span> ${esc(line)}`;
  scroll.appendChild(div);
  scroll.scrollTop = scroll.scrollHeight;
}
// Pad rows into aligned monospace columns (CSS keeps white-space: pre-wrap).
function svCols(headers, rows) {
  const w = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i] ?? '').length)));
  const fmt = (arr) => arr.map((c, i) => String(c ?? '').padEnd(w[i])).join('  ');
  return [fmt(headers), fmt(w.map((x) => '─'.repeat(x))), ...rows.map(fmt)].join('\n');
}
// Show a transient line while a (possibly slow, beacon) call is in flight.
async function svPending(fn) {
  const p = svPrint('hint', '· running… (a beacon answers on its next check-in)');
  try { return await fn(); } finally { p.remove(); }
}

function svWelcome() {
  svPrint('head', 'Sliver console — bridge-backed. Commands run over the operator connection.');
  svHelp();
}
function svHelp() {
  svPrint('out', [
    'server commands:',
    '  sessions            list interactive sessions',
    '  beacons             list beacons',
    '  agents              list all live agents',
    '  jobs                list listener jobs',
    '  use <id|name>       interact with an agent (or use the dropdown)',
    '  background          stop interacting with the current agent',
    '  help / clear',
    '',
    'agent commands (after `use`):',
    '  info                agent metadata',
    '  pwd / cd <path>     working directory',
    '  ls [path]           list a directory',
    '  ps                  process list',
    '  netstat / ifconfig  network',
    '  screenshot          capture desktop (renders inline)',
    '  execute <cmd…>      run a shell command (alias: shell/run)',
    '  interactive         (beacon) open an interactive session',
    '  execute-assembly <path-on-bridge> [args…]   run a .NET assembly in memory',
    '  kill                terminate the agent',
  ].join('\n'));
}

const svConsole = makeConsoleInput($('#sv-cmd'), SV_COMMANDS,
  (matches) => svPrint('hint', matches.join('    ')));
$('#sv-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('#sv-cmd');
  const line = input.value.trim();
  input.value = '';
  if (line) { svConsole.remember(line); svRun(line); }
});
$('#sv-clear').onclick = () => { svScroll().innerHTML = ''; };
$('#sv-help').onclick = () => svHelp();
$('#sv-agent').addEventListener('change', (e) => {
  const id = e.target.value;
  if (id) svUse(id); else svBackground();
});

async function svRun(line) {
  svEcho(line);
  const parts = line.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const arg = parts.slice(1).join(' ');
  try {
    switch (cmd) {
      case 'help': return svHelp();
      case 'clear': return void (svScroll().innerHTML = '');
      case 'sessions': return svList('session');
      case 'beacons': return svList('beacon');
      case 'agents': return svList('all');
      case 'jobs': return svJobs();
      case 'use': return svUseByQuery(arg);
      case 'background': case 'bg': return svBackground();
      default: return svAgentCmd(cmd, arg);
    }
  } catch (e) { svPrint('err', e.message); }
}

function svUseByQuery(q) {
  if (!q) { svPrint('err', 'usage: use <agent id or name>'); return; }
  const rec = STATE.order.map((id) => STATE.agents[id]).find((r) =>
    r.a.ID === q || r.a.ID.startsWith(q) || (r.a.Name && r.a.Name.toLowerCase() === q.toLowerCase()));
  if (!rec) { svPrint('err', `no agent matching '${q}'`); return; }
  svUse(rec.a.ID);
}
function svUse(id) {
  const rec = STATE.agents[id];
  if (!rec) { svPrint('err', 'agent not found'); return; }
  SV.current = id;
  const nm = agentName(rec.a);
  $('#sv-prompt').innerHTML = `sliver (${esc(nm)})&nbsp;&gt;`;
  $('#sv-current').textContent = `${nm} · ${rec.kind} · ${rec.a.OS}/${rec.a.Arch}`;
  const sel = $('#sv-agent'); if (sel.value !== id) sel.value = id;
  svPrint('hint', `now interacting with ${nm} — ${id}`);
  $('#sv-cmd').focus();
}
function svBackground() {
  SV.current = null;
  $('#sv-prompt').innerHTML = 'sliver&nbsp;&gt;';
  $('#sv-current').textContent = 'no agent — server commands only';
  $('#sv-agent').value = '';
  svPrint('hint', 'backgrounded');
}

function svList(kind) {
  const rows = [];
  for (const id of STATE.order) {
    const rec = STATE.agents[id];
    if (rec.kind === 'dead') continue;
    if (kind !== 'all' && rec.kind !== kind) continue;
    const a = rec.a;
    rows.push([a.ID.slice(0, 8), agentName(a), `${a.Username}@${a.Hostname}`,
      `${a.OS}/${a.Arch}`, a.Transport, ago(a.LastCheckin)]);
  }
  if (!rows.length) { svPrint('hint', `no ${kind === 'all' ? 'agents' : kind + 's'}`); return; }
  svPrint('out', svCols(['ID', 'NAME', 'USER@HOST', 'OS/ARCH', 'TRANSPORT', 'LAST'], rows));
}
async function svJobs() {
  const jobs = await api('GET', '/api/jobs');
  if (!jobs || !jobs.length) { svPrint('hint', 'no active jobs'); return; }
  svPrint('out', svCols(['ID', 'NAME', 'PROTO', 'PORT', 'DESCRIPTION'],
    jobs.map((j) => [j.ID, j.Name, j.Protocol, j.Port, j.Description])));
}

async function svAgentCmd(cmd, arg) {
  if (!SV.current) {
    svPrint('err', `unknown command '${cmd}'. Type 'help'. (agent commands need \`use <agent>\` first)`);
    return;
  }
  const id = SV.current;
  switch (cmd) {
    case 'info': return svInfo(id);
    case 'pwd': { const r = await svPending(() => api('GET', `/api/target/${id}/pwd`)); svPrint('out', r.Path || '—'); return; }
    case 'cd': { const r = await svPending(() => api('POST', `/api/target/${id}/cd`, { path: arg || '/' })); svPrint('out', r.Path || '—'); return; }
    case 'ls': return svLs(id, arg);
    case 'ps': return svPs(id);
    case 'netstat': case 'ifconfig': return svNet(id);
    case 'screenshot': return svShot(id);
    case 'kill': { await svPending(() => api('POST', `/api/target/${id}/kill`)); svPrint('out', 'kill sent'); loadAgents(); return; }
    case 'interactive': return svInteractive(id);
    case 'execute-assembly': case 'ea': return svExecAssembly(id, arg);
    case 'execute': case 'shell': case 'run':
      if (!arg) { svPrint('err', `usage: ${cmd} <command>`); return; }
      return svExec(id, arg);
    default:
      svPrint('err', `unknown command '${cmd}'. Type 'help'.`);
  }
}
function svInfo(id) {
  const a = STATE.agents[id].a;
  const rows = [
    ['id', a.ID], ['name', agentName(a)], ['user', a.Username], ['host', a.Hostname],
    ['os/arch', `${a.OS}/${a.Arch}`], ['transport', a.Transport],
    ['remote', remoteAddr(a)], ['pid', a.PID], ['version', a.Version],
    ['last check-in', ago(a.LastCheckin)],
  ];
  svPrint('out', rows.map(([k, v]) => `${k.padEnd(14)}${v ?? '—'}`).join('\n'));
}
async function svLs(id, path) {
  const r = await svPending(() => api('POST', `/api/target/${id}/ls`, { path: path || '' }));
  const files = (r.Files || []).filter((f) => f.Name !== '.')
    .sort((a, b) => (b.IsDir - a.IsDir) || a.Name.localeCompare(b.Name));
  svPrint('hint', r.Path || path || '');
  if (!files.length) { svPrint('out', '(empty)'); return; }
  svPrint('out', svCols(['MODE', 'SIZE', 'NAME'],
    files.map((f) => [f.Mode || '', f.IsDir ? '<dir>' : fmtSize(f.Size), f.Name])));
}
async function svPs(id) {
  const r = await svPending(() => api('GET', `/api/target/${id}/ps`));
  const procs = (r.Processes || []).slice().sort((a, b) => a.Pid - b.Pid);
  if (!procs.length) { svPrint('out', 'no processes'); return; }
  svPrint('out', svCols(['PID', 'PPID', 'OWNER', 'EXECUTABLE'],
    procs.map((p) => [p.Pid, p.Ppid, p.Owner, p.Executable])));
}
async function svNet(id) {
  const [ifc, ns] = await svPending(() => Promise.all([
    api('GET', `/api/target/${id}/ifconfig`).catch(() => null),
    api('GET', `/api/target/${id}/netstat`).catch(() => null),
  ]));
  let s = '';
  if (ifc && ifc.NetInterfaces) {
    s += '── interfaces ──\n';
    for (const i of ifc.NetInterfaces) s += `${i.Name}  ${(i.IPAddresses || []).join(', ')}\n`;
  }
  if (ns && ns.Entries) {
    s += '\n── connections ──\n';
    for (const e of ns.Entries) s += `${e.Protocol}\t${e.LocalAddr?.Ip}:${e.LocalAddr?.Port}\t${e.RemoteAddr?.Ip}:${e.RemoteAddr?.Port}\t${e.SkState}\n`;
  }
  svPrint('out', s || 'no data');
}
async function svShot(id) {
  const r = await svPending(() => api('GET', `/api/target/${id}/screenshot`));
  if (!r.data) { svPrint('err', 'no image data'); return; }
  const div = el('div', 'sv-line out');
  const img = el('img');
  img.src = `data:image/png;base64,${r.data}`;
  img.style.maxWidth = '100%'; img.style.borderRadius = '6px'; img.style.marginTop = '4px';
  div.appendChild(img);
  svScroll().appendChild(div);
  svScroll().scrollTop = svScroll().scrollHeight;
}
async function svExec(id, cmdline) {
  const r = await svPending(() => api('POST', `/api/target/${id}/execute`, { cmd: cmdline }));
  const res = r.async ? await svPending(() => svPollTask(id, r.taskId)) : r;
  const out = (res.stdout || '').replace(/\s+$/, '');
  const err = (res.stderr || '').replace(/\s+$/, '');
  if (out) svPrint('out', out);
  if (err) svPrint('err', err);
  if (!out && !err && res.status) svPrint('err', `[exit ${res.status}]`);
}
async function svPollTask(id, taskId) {
  const start = Date.now();
  while (Date.now() - start < 30 * 60 * 1000) {
    await sleep(3000);
    let r; try { r = await api('GET', `/api/target/${id}/task/${taskId}`); } catch { continue; }
    if (r.done) return r;
  }
  throw new Error('timed out waiting for beacon result');
}
async function svInteractive(id) {
  if (STATE.agents[id].kind !== 'beacon') { svPrint('err', 'interactive is for beacons — a session is already interactive'); return; }
  await svPending(() => api('POST', `/api/target/${id}/interactive`));
  svPrint('out', 'session requested — it will appear in the sidebar on the beacon’s next check-in');
  loadAgents();
}
async function svExecAssembly(id, arg) {
  const parts = arg.split(/\s+/).filter(Boolean);
  if (!parts.length) { svPrint('err', 'usage: execute-assembly <path-on-bridge-host> [args…]'); return; }
  const path = parts[0], args = parts.slice(1).join(' ');
  const r = await svPending(() => api('POST', `/api/target/${id}/execute-assembly`, { path, args }));
  const out = (r.output || '').replace(/\s+$/, '');
  svPrint(out ? 'out' : 'hint', out || '(assembly ran — no output returned)');
}

// =====================================================================
// event log
// =====================================================================
let LOG_COUNT = 0;
const logEl = $('#eventlog');
$('#log-head').onclick = toggleLog;
$('#log-toggle-top').onclick = toggleLog;
function toggleLog() {
  logEl.classList.toggle('collapsed');
  $('#log-chevron').innerHTML = logEl.classList.contains('collapsed') ? '&#9650;' : '&#9660;';
}
function logEvent(ev) {
  const body = $('#events-body');
  let cls = '';
  if (/connected/i.test(ev.type)) cls = 'connect';
  else if (/disconnected/i.test(ev.type)) cls = 'disconnect';
  else if (/job/i.test(ev.type)) cls = 'job';
  const who = ev.session ? ` ${ev.session.Name}@${ev.session.Hostname}`
    : ev.job ? ` ${ev.job.Name}:${ev.job.Port}` : '';
  const div = el('div', 'ev ' + cls);
  div.innerHTML = `<span class="t">${new Date().toLocaleTimeString()}</span>` +
    `<span class="msg">${esc(ev.type)}${esc(who)}</span>`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
  while (body.children.length > 200) body.removeChild(body.firstChild);
  LOG_COUNT++;
  $('#log-count').textContent = LOG_COUNT + ' events';
}
function startEvents() {
  const es = new EventSource('/api/events');
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    logEvent(ev);
    if (/session|beacon/i.test(ev.type)) loadAgents();
    if (/job/i.test(ev.type) && STATE.view === 'listeners') loadJobs();
  };
  es.onerror = () => { /* EventSource auto-reconnects */ };
}

// =====================================================================
// boot
// =====================================================================
api('GET', '/api/config').then((c) => {
  $('#conn').innerHTML = `<span class="op">${esc(c.operator)}</span> @ ${esc(c.server)}`;
}).catch((e) => { $('#conn').textContent = 'error: ' + e.message; });

// Bookmarkable views via #listeners / #generate and agents via #a/<id>[/<tab>].
function applyHash() {
  const h = location.hash.replace('#', '');
  if (['listeners', 'pivots', 'generate', 'profiles', 'implants', 'sliver', 'help', 'agents'].includes(h)) { setView(h); return; }
  const m = h.match(/^a\/([^/]+)(?:\/(\w+))?$/);
  if (m && STATE.agents[m[1]]) {
    if (STATE.selected !== m[1]) selectAgent(m[1]);
    if (m[2]) switchTab(m[2]);
  }
}
window.addEventListener('hashchange', applyHash);

initTheme();
initTabReorder();
tickClock();
setInterval(tickClock, 1000);
loadInterfaces();
applyHash();
loadAgents();
setInterval(loadAgents, 5000);
startEvents();
