'use strict';

/* Sliver Web GUI front-end — Cobalt Strike-style operator console: a menu bar,
   a target graph/table, and a resizable tabbed console dock. Talks to the Go
   bridge's REST + SSE API. Every action maps to a real, native Sliver command
   or RPC — nothing here is decorative. */

// ---------- tiny helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const elIn = (root, name) => root.querySelector(`[data-el="${name}"]`);
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
function readFileAsBase64(file) {
  return file.arrayBuffer().then((buf) => {
    let bin = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  });
}

// ---------- global state ----------
const STATE = {
  agents: {},   // id -> { a, kind: session|beacon|dead, isBeacon }
  order: [],
  interfaces: [], // [{name, ip, version, up}]
  filter: '',
  panels: {},   // agentId -> { cwd }
  nodePos: {},  // agentId -> {x,y} — manually dragged graph node positions
  tabNames: {}, // id -> custom tab name
};

// =====================================================================
// interfaces (host combo/select population)
// =====================================================================
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
  if (prev && Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
  else if (opts.default != null) {
    const wanted = Array.from(sel.options).find((o) => o.value === opts.default);
    if (wanted) sel.value = opts.default;
  }
}
// Fill a <datalist> paired with a text <input> — the host field is then both a
// pick-from-list dropdown (interface → IP) *and* a free-text box (hostnames,
// redirectors, domain-fronted names all work).
function fillDatalist(dl, opts) {
  opts = opts || {};
  dl.innerHTML = '';
  if (opts.allInterfaces) dl.appendChild(new Option('0.0.0.0 · all interfaces', '0.0.0.0'));
  for (const i of STATE.interfaces) {
    if (opts.v4only && i.version !== 4) continue;
    dl.appendChild(new Option(`${i.ip} · ${i.name}${i.version === 6 ? ' (v6)' : ''}${i.up ? '' : ' [down]'}`, i.ip));
  }
}
function preferredV4() {
  const isVirtual = (n) => /^(lo|docker|br-|veth|virbr|vmnet|tun|tap|utun|zt)/i.test(n);
  const v4 = STATE.interfaces.filter((i) => i.version === 4 && i.ip !== '127.0.0.1');
  const preferred = v4.find((i) => !isVirtual(i.name)) || v4[0];
  return preferred ? preferred.ip : '';
}
async function loadInterfaces() {
  try { STATE.interfaces = await api('GET', '/api/interfaces'); } catch { STATE.interfaces = []; }
  fillIfaceSelect($('#mlHost'), { allInterfaces: true, v4only: true, default: '0.0.0.0' });
  fillIfaceSelect($('#mgHost'), { v4only: true, default: preferredV4() });
  updateBindWarning();
}

// VPN/tunnel bind guard (see Listeners modal) — a listener bound to a VPN
// interface's IP can fail to restore at boot (interface not up yet), and the
// stale DB record then blocks that port for every protocol until cleared.
const VPN_IFACE = /^(tun|tap|wg|ppp|utun|ligolo)/i;
function ifaceForIP(ip) {
  const i = STATE.interfaces.find((x) => x.ip === ip);
  return i ? i.name : '';
}
function isVPNBind(ip) {
  return !!ip && ip !== '0.0.0.0' && VPN_IFACE.test(ifaceForIP(ip));
}
function updateBindWarning() {
  const note = $('#mlWarn');
  const ip = $('#mlHost').value.trim();
  if (!isVPNBind(ip)) { note.style.display = 'none'; return; }
  const iface = ifaceForIP(ip);
  note.style.display = '';
  note.innerHTML = `<b>${esc(iface)}</b> is a VPN/tunnel interface. It may not exist yet when the Sliver ` +
    `server starts at boot, so a listener bound to <b>${esc(ip)}</b> will fail to restore and strand this ` +
    `port until the leftover record is removed. Prefer <b>0.0.0.0</b> — it already covers ${esc(iface)}.`;
}
$('#mlHost').addEventListener('input', updateBindWarning);

// =====================================================================
// menu bar (Sliver | View | Payloads | Listeners | Help)
// =====================================================================
const menubar = $('#menubar');
function closeMenus() { $$('.mbtn.open', menubar).forEach((m) => m.classList.remove('open')); }
$$('.mbtn', menubar).forEach((m) => {
  m.querySelector(':scope > button').addEventListener('click', (e) => {
    e.stopPropagation();
    const wasOpen = m.classList.contains('open');
    closeMenus();
    if (!wasOpen) m.classList.add('open');
  });
});
document.addEventListener('click', closeMenus);
$$('.ddown button', menubar).forEach((b) => {
  b.addEventListener('click', () => {
    const act = b.dataset.act;
    if (act === 'view-table') $('#btnTable').click();
    else if (act === 'view-graph') $('#btnGraph').click();
    else if (act === 'open-tab') openUtilTab(b.dataset.tab);
    else if (act === 'modal') {
      if (b.dataset.modal === 'listener') resetListenerModal();
      openModal(b.dataset.modal);
    }
    else if (act === 'about') openAbout();
    closeMenus();
  });
});

// =====================================================================
// toolbar: graph/table toggle, target filter
// =====================================================================
const btnGraph = $('#btnGraph'), btnTable = $('#btnTable');
const graphPanel = $('#graphPanel'), tablePanel = $('#tablePanel');
btnGraph.onclick = () => { btnGraph.classList.add('active'); btnTable.classList.remove('active'); graphPanel.classList.remove('hidden'); tablePanel.classList.add('hidden'); };
btnTable.onclick = () => { btnTable.classList.add('active'); btnGraph.classList.remove('active'); tablePanel.classList.remove('hidden'); graphPanel.classList.add('hidden'); };
$('#target-filter').addEventListener('input', (e) => { STATE.filter = e.target.value.toLowerCase(); renderTable(); renderGraph(); });
function matchesFilter(id) {
  if (!STATE.filter) return true;
  const a = STATE.agents[id].a;
  const hay = `${a.Name} ${a.Username} ${a.Hostname} ${a.OS} ${a.RemoteAddress}`.toLowerCase();
  return hay.includes(STATE.filter);
}

// =====================================================================
// agent identity helpers (ported as-is)
// =====================================================================
let RENAMED = {};
try { RENAMED = JSON.parse(localStorage.getItem('sliver.renamed')) || {}; } catch { RENAMED = {}; }
function markRenamed(id, renamed) {
  if (renamed) RENAMED[id] = true; else delete RENAMED[id];
  try { localStorage.setItem('sliver.renamed', JSON.stringify(RENAMED)); } catch {}
}
function domainOf(a) {
  const u = a.Username || '';
  const bs = u.indexOf('\\');
  if (bs <= 0) return '';
  const d = u.slice(0, bs);
  if (!d || d === '.' || d.toLowerCase() === (a.Hostname || '').toLowerCase()) return '';
  return d;
}
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
function remoteAddr(a) {
  const r = a.RemoteAddress || '';
  const m = r.match(/^tcp\((.+)\)->(.+)$/);
  return m ? `${m[2]} (via ${m[1]})` : r;
}
// privLevel approximates Cobalt Strike's medium/high integrity icon from the
// one signal we actually have — the reported username — since Sliver's
// session/beacon list doesn't carry an explicit privilege-level field.
function privLevel(a) {
  const u = (a.Username || '').toLowerCase();
  if (/(^|\\)(system|root)$/.test(u) || u.startsWith('nt authority\\')) return 'high';
  return 'medium';
}
function monitorColor(rec) {
  if (rec.kind === 'dead') return 'var(--dead)';
  return privLevel(rec.a) === 'high' ? 'var(--priv-high)' : 'var(--priv-med)';
}
function sleepLabel(rec) {
  if (rec.kind === 'dead' || !rec.isBeacon) return '—';
  const secs = (ns) => Math.max(0, Math.round((ns || 0) / 1e9));
  return `${secs(rec.a.Interval)}s / ${secs(rec.a.Jitter)}s`;
}
// removeAgentRecord clears one agent's record from the console: a beacon (dead
// or alive) is deleted via RmBeacon; a session has no such "just forget it"
// RPC, so a dead session is cleared via Kill instead — Sliver's Kill handler
// removes the session from its in-memory table unconditionally, even when the
// underlying connection is already gone.
async function removeAgentRecord(id, rec) {
  if (rec.isBeacon) return api('POST', `/api/target/${id}/remove`);
  return api('POST', `/api/target/${id}/kill`);
}

// =====================================================================
// loading sessions/beacons + rendering the stage (graph / table)
// =====================================================================
async function loadAgents() {
  try {
    const [sessions, beacons] = await Promise.all([api('GET', '/api/sessions'), api('GET', '/api/beacons')]);
    const map = {}; const order = [];
    for (const a of sessions || []) { map[a.ID] = { a, kind: a.IsDead ? 'dead' : 'session', isBeacon: false }; order.push(a.ID); }
    for (const a of beacons || []) { map[a.ID] = { a, kind: a.IsDead ? 'dead' : 'beacon', isBeacon: true }; order.push(a.ID); }
    STATE.agents = map; STATE.order = order;
    renderChips();
    renderTable();
    await renderGraph();
    for (const id of Object.keys(STATE.panels)) {
      const pane = ensurePane(id);
      if (pane && $(`.subtab[data-sub="info"].active`, pane)) renderInfo(id, pane);
    }
  } catch (e) {
    $('#tblBody').innerHTML = `<tr><td colspan="9" class="empty">${esc(e.message)}</td></tr>`;
  }
}
function renderChips() {
  const n = (kind) => STATE.order.filter((id) => STATE.agents[id].kind === kind).length;
  $('#chip-sessions').textContent = n('session');
  $('#chip-beacons').textContent = n('beacon');
  $('#chip-dead').textContent = n('dead');
}

function renderTable() {
  const tbody = $('#tblBody');
  const ids = STATE.order.filter(matchesFilter);
  if (!ids.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty">${STATE.filter ? 'no matches' : 'no agents connected'}</td></tr>`;
    return;
  }
  tbody.innerHTML = '';
  for (const id of ids) {
    const rec = STATE.agents[id]; const a = rec.a;
    const tr = el('tr');
    if (rec.kind === 'dead') tr.className = 'is-dead';
    tr.innerHTML =
      `<td><span class="monitor" style="background:${monitorColor(rec)}"></span></td>` +
      `<td>${esc(a.Name || agentName(a))}</td><td>${esc(a.Hostname)}</td><td>${esc(a.Username)}</td>` +
      `<td>${esc(a.Transport)}</td><td class="num">${a.PID}</td><td class="num">${esc(a.Arch)}</td>` +
      `<td class="num">${esc(ago(a.LastCheckin))}</td><td class="num">${esc(sleepLabel(rec))}</td>`;
    tr.addEventListener('click', () => openAgentConsole(id));
    tr.addEventListener('contextmenu', (e) => { e.preventDefault(); showAgentMenu(id, e.clientX, e.clientY); });
    tbody.appendChild(tr);
  }
}

// ----- graph: real agents + real pivot-chain edges (from /api/pivots) -----
function svgEl(tag, attrs) {
  const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
// Walk the PivotGraph tree, recording childID -> hostingSessionID for every
// downstream implant so the graph can draw a solid pivoted edge instead of a
// dashed direct-egress one.
function flattenPivotParents(graph) {
  const parentOf = {};
  function walk(node, parentId) {
    if (parentId) parentOf[node.ID] = parentId;
    for (const child of node.Children || []) walk(child, node.ID);
  }
  for (const root of graph?.Children || []) walk(root, null);
  return parentOf;
}
function layoutGraph(ids, parentOf) {
  const children = {}; const roots = [];
  for (const id of ids) {
    const p = parentOf[id];
    if (p && STATE.agents[p]) (children[p] = children[p] || []).push(id);
    else roots.push(id);
  }
  const positions = {};
  let yCounter = 0;
  const Y_STEP = 52, X_STEP = 190, X0 = 240;
  function place(id, depth) {
    const kids = (children[id] || []).filter((k) => k !== id);
    if (!kids.length) {
      positions[id] = { x: X0 + depth * X_STEP, y: yCounter * Y_STEP + 36 };
      yCounter++;
      return positions[id].y;
    }
    const ys = kids.map((k) => place(k, depth + 1));
    const y = ys.reduce((s, v) => s + v, 0) / ys.length;
    positions[id] = { x: X0 + depth * X_STEP, y };
    return y;
  }
  for (const r of roots) place(r, 0);
  return positions;
}
// GRAPH holds live element references so a drag can update just the moved
// node + its connected edges, without a full re-layout/re-render.
const GRAPH = { positions: {}, parentOf: {}, ids: [], nodeEls: {}, edgeEls: {} };
const ROOT_ID = '__root__';
let ROOT = { x: 60, y: 170 };
try { const saved = JSON.parse(localStorage.getItem('sliver.rootPos')); if (saved) ROOT = saved; } catch {}
function saveRootPos() { try { localStorage.setItem('sliver.rootPos', JSON.stringify(ROOT)); } catch {} }
// Root-anchored edges are every direct-egress node's edge (no pivot parent),
// which isn't tracked in GRAPH.parentOf — so moving TEAMSERVER needs its own
// edge-refresh instead of the generic per-node updateEdgesFor().
function updateEdgesForRoot() {
  for (const otherId of GRAPH.ids) {
    if (!GRAPH.parentOf[otherId]) {
      const edge = GRAPH.edgeEls[otherId];
      if (edge) { edge.setAttribute('x1', ROOT.x); edge.setAttribute('y1', ROOT.y); }
    }
  }
}
// Keeps any manual link (line + its label) touching `id` attached while it's
// being dragged — links can connect any two node types, so this is shared
// across the agent/root/custom-node drag paths rather than duplicated in each.
function updateCustomLinksFor(id) {
  for (const linkId in CUSTOM_LINKS) {
    const link = CUSTOM_LINKS[linkId];
    if (link.from !== id && link.to !== id) continue;
    const from = GRAPH.positions[link.from], to = GRAPH.positions[link.to];
    if (!from || !to) continue;
    const line = GRAPH.linkEls[linkId];
    if (line) { line.setAttribute('x1', from.x); line.setAttribute('y1', from.y); line.setAttribute('x2', to.x); line.setAttribute('y2', to.y); }
    const label = GRAPH.linkLabelEls[linkId];
    if (label) { label.setAttribute('x', (from.x + to.x) / 2); label.setAttribute('y', (from.y + to.y) / 2 - 5); }
  }
}
// svgPoint converts a mouse/pointer event's client coordinates into the SVG's
// own viewBox coordinate space, accounting for however the browser has
// scaled/letterboxed the element — needed since the graph panel can be any
// pixel size.
function svgPoint(svg, e) {
  const pt = svg.createSVGPoint();
  pt.x = e.clientX; pt.y = e.clientY;
  return pt.matrixTransform(svg.getScreenCTM().inverse());
}
// Recompute and redraw just the edges touching `id` (its own edge to its
// parent, plus any edges from nodes pivoted through it) after a drag. Custom
// annotation nodes have no edges, so this is a no-op for them.
function updateEdgesFor(id) {
  const p = GRAPH.positions[id];
  const ownEdge = GRAPH.edgeEls[id];
  if (ownEdge) { ownEdge.setAttribute('x2', p.x); ownEdge.setAttribute('y2', p.y); }
  for (const otherId of GRAPH.ids) {
    if (GRAPH.parentOf[otherId] === id) {
      const edge = GRAPH.edgeEls[otherId];
      if (edge) { edge.setAttribute('x1', p.x); edge.setAttribute('y1', p.y); }
    }
  }
}
// Node dragging uses native Pointer Capture: once a node captures the pointer
// on pointerdown, the browser guarantees pointermove/pointerup keep firing on
// that same element for the rest of the gesture — no window-level listeners,
// no "the cursor moved off the small SVG node and the drag died" edge cases.
const DRAG = { id: null, offset: { x: 0, y: 0 }, moved: false };
function wireNodeDrag(svg, g, id) {
  g.style.touchAction = 'none';
  g.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    if (LINKING.from) { completeLink(id); return; }
    g.setPointerCapture(e.pointerId);
    DRAG.id = id; DRAG.moved = false;
    const pt = svgPoint(svg, e);
    DRAG.offset.x = pt.x - GRAPH.positions[id].x;
    DRAG.offset.y = pt.y - GRAPH.positions[id].y;
  });
  g.addEventListener('pointermove', (e) => {
    if (DRAG.id !== id) return;
    DRAG.moved = true;
    const pt = svgPoint(svg, e);
    const pos = { x: pt.x - DRAG.offset.x, y: pt.y - DRAG.offset.y };
    GRAPH.positions[id] = pos;
    if (id === ROOT_ID) { ROOT.x = pos.x; ROOT.y = pos.y; }
    else if (STATE.agents[id]) STATE.nodePos[id] = pos;
    else if (CUSTOM_NODES[id]) { CUSTOM_NODES[id].x = pos.x; CUSTOM_NODES[id].y = pos.y; }
    g.setAttribute('transform', `translate(${pos.x},${pos.y})`);
    if (id === ROOT_ID) updateEdgesForRoot(); else updateEdgesFor(id);
    updateCustomLinksFor(id);
  });
  g.addEventListener('pointerup', (e) => {
    if (DRAG.id !== id) return;
    g.releasePointerCapture(e.pointerId);
    const wasMoved = DRAG.moved;
    DRAG.id = null;
    if (!wasMoved) { if (STATE.agents[id]) openAgentConsole(id); }
    else if (id === ROOT_ID) saveRootPos();
    else if (CUSTOM_NODES[id]) saveCustomNodes();
  });
}

// ----- custom annotation nodes (operator notes on the graph — not real
// agents; e.g. marking a known-but-not-yet-compromised host) -----
let CUSTOM_NODES = {};
try { CUSTOM_NODES = JSON.parse(localStorage.getItem('sliver.customNodes')) || {}; } catch { CUSTOM_NODES = {}; }
function saveCustomNodes() { try { localStorage.setItem('sliver.customNodes', JSON.stringify(CUSTOM_NODES)); } catch {} }
function addCustomNode(x, y) {
  const label = prompt('Node label:');
  if (!label || !label.trim()) return;
  const id = 'custom-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  CUSTOM_NODES[id] = { label: label.trim(), x, y };
  saveCustomNodes();
  renderGraph();
}
function renameCustomNode(id) {
  const node = CUSTOM_NODES[id]; if (!node) return;
  const name = prompt('Rename node:', node.label);
  if (!name || !name.trim()) return;
  node.label = name.trim();
  saveCustomNodes();
  renderGraph();
}
function deleteCustomNode(id) {
  if (!confirm('Delete this node?')) return;
  delete CUSTOM_NODES[id];
  saveCustomNodes();
  renderGraph();
}
function showCustomNodeMenu(id, x, y) {
  if (LINKING.from) cancelLinking();
  ctx.innerHTML = `<button data-a="rename">Rename&hellip;</button><button data-a="link">Link to&hellip;</button><hr><button class="danger" data-a="delete">Delete</button>`;
  $$('button[data-a]', ctx).forEach((b) => b.addEventListener('click', (e) => {
    e.stopPropagation();
    if (b.dataset.a === 'rename') renameCustomNode(id);
    else if (b.dataset.a === 'link') startLinking(id);
    else if (b.dataset.a === 'delete') deleteCustomNode(id);
    hideMenu();
  }));
  placeMenu(x, y);
}
function showRootMenu(x, y) {
  if (LINKING.from) cancelLinking();
  ctx.innerHTML = `<button data-a="link">Link to&hellip;</button>`;
  $$('button[data-a]', ctx).forEach((b) => b.addEventListener('click', (e) => {
    e.stopPropagation();
    if (b.dataset.a === 'link') startLinking(ROOT_ID);
    hideMenu();
  }));
  placeMenu(x, y);
}

// ----- manual links (operator-drawn, named connections between any two
// nodes — real agents, custom nodes, or TEAMSERVER — for annotating attack
// paths/relationships the auto pivot-chain edges don't cover) -----
let CUSTOM_LINKS = {};
try { CUSTOM_LINKS = JSON.parse(localStorage.getItem('sliver.customLinks')) || {}; } catch { CUSTOM_LINKS = {}; }
function saveCustomLinks() { try { localStorage.setItem('sliver.customLinks', JSON.stringify(CUSTOM_LINKS)); } catch {} }
function linkEndpointExists(id) { return id === ROOT_ID || !!STATE.agents[id] || !!CUSTOM_NODES[id]; }

const LINKING = { from: null, tempLine: null };
function updateLinkingCursor(on) { const p = $('#graphPanel'); if (p) p.classList.toggle('linking', on); }
function cancelLinking() {
  LINKING.from = null;
  if (LINKING.tempLine) { LINKING.tempLine.remove(); LINKING.tempLine = null; }
  updateLinkingCursor(false);
}
function startLinking(fromId) {
  LINKING.from = fromId;
  updateLinkingCursor(true);
}
function completeLink(toId) {
  const fromId = LINKING.from;
  cancelLinking();
  if (!fromId || fromId === toId) return;
  const label = prompt('Label for this link (optional):') || '';
  const id = 'link-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  CUSTOM_LINKS[id] = { from: fromId, to: toId, label: label.trim() };
  saveCustomLinks();
  renderGraph();
}
function editLinkLabel(id) {
  const link = CUSTOM_LINKS[id]; if (!link) return;
  const label = prompt('Link label:', link.label || '');
  if (label == null) return;
  link.label = label.trim();
  saveCustomLinks();
  renderGraph();
}
function deleteLink(id) {
  if (!confirm('Delete this link?')) return;
  delete CUSTOM_LINKS[id];
  saveCustomLinks();
  renderGraph();
}
function showLinkMenu(id, x, y) {
  if (LINKING.from) cancelLinking();
  ctx.innerHTML = `<button data-a="edit">Edit&hellip;</button><hr><button class="danger" data-a="delete">Delete</button>`;
  $$('button[data-a]', ctx).forEach((b) => b.addEventListener('click', (e) => {
    e.stopPropagation();
    if (b.dataset.a === 'edit') editLinkLabel(id);
    else if (b.dataset.a === 'delete') deleteLink(id);
    hideMenu();
  }));
  placeMenu(x, y);
}
// Graph removed
window.addEventListener('keydown', (e) => { if (e.key === 'Escape' && LINKING.from) cancelLinking(); });
function showCanvasMenu(svg, x, y) {
  if (LINKING.from) { cancelLinking(); return; }
  const pt = svgPoint(svg, { clientX: x, clientY: y });
  ctx.innerHTML = `<button data-a="add">Add Node Here&hellip;</button><hr><button data-a="refresh">Refresh</button>`;
  $$('button[data-a]', ctx).forEach((b) => b.addEventListener('click', (e) => {
    e.stopPropagation();
    if (b.dataset.a === 'add') addCustomNode(pt.x, pt.y);
    else if (b.dataset.a === 'refresh') loadAgents();
    hideMenu();
  }));
  placeMenu(x, y);
}

async function renderGraph() {
  const svg = $('#graphSvg');
  let parentOf = {};
  try { parentOf = flattenPivotParents(await api('GET', '/api/pivots')); } catch {}
  const ids = STATE.order.filter(matchesFilter);
  const computed = layoutGraph(ids, parentOf);
  // A node the operator has manually dragged keeps its dragged position;
  // everything else uses the auto tree layout.
  const positions = {};
  for (const id of ids) positions[id] = STATE.nodePos[id] || computed[id];
  GRAPH.positions = positions; GRAPH.parentOf = parentOf; GRAPH.ids = ids;
  GRAPH.nodeEls = {}; GRAPH.edgeEls = {}; GRAPH.linkEls = {}; GRAPH.linkLabelEls = {};
  // Every node type's position must be known before any edge/link is drawn.
  GRAPH.positions[ROOT_ID] = ROOT;
  for (const id in CUSTOM_NODES) GRAPH.positions[id] = { x: CUSTOM_NODES[id].x, y: CUSTOM_NODES[id].y };

  svg.innerHTML = '';
  const customYs = Object.values(CUSTOM_NODES).map((n) => n.y + 20);
  const maxY = Math.max(170, ...Object.values(positions).map((p) => p.y + 36), ...Object.values(computed).map((p) => p.y + 36), ...customYs);
  svg.setAttribute('viewBox', `0 0 900 ${maxY + 20}`);

  for (const id of ids) {
    const rec = STATE.agents[id];
    const p = positions[id];
    const parentPos = (parentOf[id] && positions[parentOf[id]]) || ROOT;
    const isPivoted = !!(parentOf[id] && STATE.agents[parentOf[id]]);
    const color = rec.kind === 'dead' ? 'var(--dead)' : (isPivoted ? 'var(--gold)' : 'var(--ok)');
    const line = svgEl('line', { x1: parentPos.x, y1: parentPos.y, x2: p.x, y2: p.y, class: 'edge ' + (isPivoted ? '' : 'egress'), stroke: color });
    GRAPH.edgeEls[id] = line;
    svg.appendChild(line);
  }

  // Manual links: drawn once endpoints exist; a link whose endpoint was
  // actually deleted (not just hidden by the filter box) is pruned instead of
  // lingering invisibly forever.
  let prunedLinks = false;
  for (const linkId in CUSTOM_LINKS) {
    const link = CUSTOM_LINKS[linkId];
    if (!linkEndpointExists(link.from) || !linkEndpointExists(link.to)) { delete CUSTOM_LINKS[linkId]; prunedLinks = true; continue; }
    const from = GRAPH.positions[link.from], to = GRAPH.positions[link.to];
    if (!from || !to) continue; // filtered out of view right now — keep the link, just don't draw it
    const line = svgEl('line', { x1: from.x, y1: from.y, x2: to.x, y2: to.y, class: 'edge custom-link' });
    line.addEventListener('contextmenu', (e) => { e.preventDefault(); e.stopPropagation(); showLinkMenu(linkId, e.clientX, e.clientY); });
    GRAPH.linkEls[linkId] = line;
    svg.appendChild(line);
    if (link.label) {
      const mx = (from.x + to.x) / 2, my = (from.y + to.y) / 2;
      const label = svgEl('text', { x: mx, y: my - 5, 'text-anchor': 'middle', class: 'link-label' });
      label.textContent = link.label;
      label.addEventListener('contextmenu', (e) => { e.preventDefault(); e.stopPropagation(); showLinkMenu(linkId, e.clientX, e.clientY); });
      GRAPH.linkLabelEls[linkId] = label;
      svg.appendChild(label);
    }
  }
  if (prunedLinks) saveCustomLinks();

  const rootG = svgEl('g', { class: 'gnode root', transform: `translate(${ROOT.x},${ROOT.y})` });
  rootG.innerHTML = `<rect x="-34" y="-16" width="68" height="32" rx="3" fill="#2c2e32" stroke="#1c1d20"/>
    <text y="4" text-anchor="middle" class="name" style="fill:var(--graph-ink)">TEAMSERVER</text>`;
  rootG.addEventListener('contextmenu', (e) => { e.preventDefault(); showRootMenu(e.clientX, e.clientY); });
  wireNodeDrag(svg, rootG, ROOT_ID);
  GRAPH.nodeEls[ROOT_ID] = rootG;
  svg.appendChild(rootG);
  for (const id of ids) {
    const rec = STATE.agents[id]; const a = rec.a; const p = positions[id];
    const color = monitorColor(rec);
    const g = svgEl('g', { class: 'gnode' + (rec.kind === 'dead' ? ' dead' : ''), transform: `translate(${p.x},${p.y})` });
    g.innerHTML =
      `<circle r="9" fill="${rec.kind === 'dead' ? '#3a3d42' : color}" fill-opacity="${rec.kind === 'dead' ? '1' : '0.24'}" stroke="${color}" stroke-width="2"/>
       <circle r="3" fill="${color}"/>
       <text class="name" y="-18" text-anchor="middle">${esc(a.Name || agentName(a))}</text>
       <text class="sub" y="6" text-anchor="middle">${esc(agentName(a))}</text>
       <text class="sub" y="22" text-anchor="middle">${esc(a.Hostname)}</text>`;
    g.addEventListener('contextmenu', (e) => { e.preventDefault(); showAgentMenu(id, e.clientX, e.clientY); });
    wireNodeDrag(svg, g, id);
    GRAPH.nodeEls[id] = g;
    svg.appendChild(g);
  }
  for (const id in CUSTOM_NODES) {
    const node = CUSTOM_NODES[id];
    const g = svgEl('g', { class: 'gnode custom', transform: `translate(${node.x},${node.y})` });
    g.innerHTML =
      `<rect x="-34" y="-12" width="68" height="24" rx="4" fill="var(--panel-raised)" fill-opacity="0.92" stroke="var(--ink-faint)" stroke-dasharray="3 2"/>
       <text class="name" y="4" text-anchor="middle" style="fill:var(--ink)">${esc(node.label)}</text>`;
    g.addEventListener('contextmenu', (e) => { e.preventDefault(); showCustomNodeMenu(id, e.clientX, e.clientY); });
    wireNodeDrag(svg, g, id);
    GRAPH.nodeEls[id] = g;
    svg.appendChild(g);
  }
}
const gp = $('#graphPanel');
if (gp) gp.addEventListener('contextmenu', (e) => {
  if (e.target.closest('.gnode')) return;
  e.preventDefault();
  showCanvasMenu($('#graphSvg'), e.clientX, e.clientY);
});

// =====================================================================
// context menu (Interact / Access / Explore / Pivoting / Remove / Kill)
// =====================================================================
const ctx = $('#ctxmenu');
function placeMenu(x, y) {
  ctx.hidden = false; ctx.style.left = '0px'; ctx.style.top = '0px';
  const r = ctx.getBoundingClientRect();
  ctx.style.left = Math.min(x, window.innerWidth - r.width - 8) + 'px';
  ctx.style.top = Math.min(y, window.innerHeight - r.height - 8) + 'px';
}
function hideMenu() { ctx.hidden = true; }
document.addEventListener('click', hideMenu);
document.addEventListener('scroll', hideMenu, true);
window.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideMenu(); });

function showAgentMenu(id, x, y) {
  if (LINKING.from) cancelLinking();
  const rec = STATE.agents[id]; if (!rec) return;
  const dead = rec.kind === 'dead';
  const canPivot = rec.kind === 'session';
  ctx.innerHTML = `
    <button data-a="interact" ${dead ? 'disabled' : ''}>Interact</button>
    <button data-a="rename">Rename&hellip;</button>
    <button data-a="link">Link to&hellip;</button>
    <div class="cx-item">
      <button ${dead ? 'disabled' : ''}>Access <span class="arrow">&#9656;</span></button>
      <div class="submenu">
        <button data-a="getsystem" ${dead ? 'disabled' : ''}>Elevate <span class="kbd">getsystem</span></button>
        <button data-a="maketoken" ${dead ? 'disabled' : ''}>Make Token&hellip;</button>
        <button data-a="impersonate" ${dead ? 'disabled' : ''}>Impersonate Token&hellip;</button>
      </div>
    </div>
    <div class="cx-item">
      <button ${dead ? 'disabled' : ''}>Explore <span class="arrow">&#9656;</span></button>
      <div class="submenu">
        <button data-a="files" ${dead ? 'disabled' : ''}>File Browser</button>
        <button data-a="processes" ${dead ? 'disabled' : ''}>Process List</button>
        <button data-a="network" ${dead ? 'disabled' : ''}>Network</button>
        <button data-a="screenshot" ${dead ? 'disabled' : ''}>Screenshot</button>
      </div>
    </div>
    <div class="cx-item">
      <button ${dead || !canPivot ? 'disabled' : ''}>Pivoting <span class="arrow">&#9656;</span></button>
      <div class="submenu">
        <button data-a="pivots" ${dead || !canPivot ? 'disabled' : ''}>Start Pivot Listener&hellip;</button>
        <button data-a="socks" ${dead || !canPivot ? 'disabled' : ''}>Start SOCKS5 Proxy&hellip;</button>
      </div>
    </div>
    <hr>
    <button data-a="remove">Remove</button>
    <button class="danger" data-a="kill">Kill</button>`;
  $$('button[data-a]', ctx).forEach((b) => b.addEventListener('click', (e) => {
    if (b.disabled) return;
    e.stopPropagation(); runAgentAction(id, b.dataset.a); hideMenu();
  }));
  placeMenu(x, y);
}
async function runAgentAction(id, action) {
  const rec = STATE.agents[id]; if (!rec) return;
  switch (action) {
    case 'interact': openAgentConsole(id, 'terminal'); break;
    case 'rename': renameAgentDirect(id); break;
    case 'link': startLinking(id); break;
    case 'getsystem': openAgentConsole(id, 'terminal'); runInPanel(id, 'getsystem'); break;
    case 'maketoken': {
      const args = prompt('make-token <DOMAIN\\user> <password>');
      if (args) { openAgentConsole(id, 'terminal'); runInPanel(id, 'make-token ' + args); }
      break;
    }
    case 'impersonate': {
      const user = prompt('impersonate <DOMAIN\\user>');
      if (user) { openAgentConsole(id, 'terminal'); runInPanel(id, 'impersonate ' + user); }
      break;
    }
    case 'files': openAgentConsole(id, 'files'); break;
    case 'processes': openAgentConsole(id, 'processes'); break;
    case 'network': openAgentConsole(id, 'network'); break;
    case 'screenshot': openAgentConsole(id, 'screenshot'); break;
    case 'pivots':
    case 'socks': openAgentConsole(id, 'pivots'); break;
    case 'remove':
    case 'kill': {
      const verb = action === 'kill' ? 'Kill' : 'Remove';
      if (!confirm(`${verb} ${agentName(rec.a)}?`)) return;
      try {
        if (action === 'kill') await api('POST', `/api/target/${id}/kill`);
        else await removeAgentRecord(id, rec);
        closeTabDock(id);
        loadAgents();
      } catch (e) { alert(e.message); }
      break;
    }
  }
}

// =====================================================================
// dock tab framework (Event Log + per-agent panels + utility panels)
// =====================================================================
const dockTabs = $('#dockTabs');
const dockBody = $('#dockBody');

function addTab(id, label, dotColor, closable) {
  const tab = el('button', 'dtab');
  tab.dataset.tab = id;
  const displayLabel = STATE.tabNames[id] || label;
  tab.innerHTML = (dotColor ? `<span class="dot" style="background:${dotColor}"></span>` : '') +
    `<span class="tab-label">${esc(displayLabel)}</span>` + (closable ? '<span class="x">&times;</span>' : '');
  tab.addEventListener('click', (e) => { if (e.target.classList.contains('x')) { closeTabDock(id); return; } activateTab(id); });
  if (closable) {
    tab.addEventListener('dblclick', (e) => { e.stopPropagation(); renameTab(id, tab, label); });
  }
  makeTabDraggable(tab);
  dockTabs.appendChild(tab);
  return tab;
}

// ----- tab reordering -----
// Drag a dock tab left/right to reorder. The tab is moved live during dragover
// rather than on drop, so the strip previews the new order as you go. Order is
// DOM order only and is not persisted — tabs are session-scoped (agent panels
// come and go, utility panels open on demand), the same as custom tab names.
let DRAG_TAB = null;
function makeTabDraggable(tab) {
  tab.draggable = true;
  tab.addEventListener('dragstart', (e) => {
    DRAG_TAB = tab;
    tab.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    // Firefox refuses to start a drag unless some data is set.
    e.dataTransfer.setData('text/plain', tab.dataset.tab);
  });
  tab.addEventListener('dragend', () => { tab.classList.remove('dragging'); DRAG_TAB = null; });
}
// tabBefore returns the first tab whose midpoint is right of x — i.e. the one
// the dragged tab should be inserted before. Null means "past the last tab".
function tabBefore(x) {
  return $$('.dtab', dockTabs).find((t) => {
    if (t === DRAG_TAB) return false;
    const r = t.getBoundingClientRect();
    return x < r.left + r.width / 2;
  }) || null;
}
dockTabs.addEventListener('dragover', (e) => {
  if (!DRAG_TAB) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const before = tabBefore(e.clientX);
  if (before === DRAG_TAB) return;
  if (before) dockTabs.insertBefore(DRAG_TAB, before);
  else dockTabs.appendChild(DRAG_TAB);
});
dockTabs.addEventListener('drop', (e) => e.preventDefault());
function activateTab(id) {
  $$('.dtab', dockTabs).forEach((t) => t.classList.toggle('active', t.dataset.tab === id));
  $$('.dpane', dockBody).forEach((p) => p.classList.toggle('active', p.dataset.tab === id));
}
function renameTab(id, tab, defaultLabel) {
  const current = STATE.tabNames[id] || defaultLabel;
  const newName = prompt('Rename tab:', current);
  if (newName === null || newName.trim() === '') return;
  const trimmed = newName.trim();
  if (trimmed === defaultLabel) {
    delete STATE.tabNames[id];
  } else {
    STATE.tabNames[id] = trimmed;
  }
  const label = tab.querySelector('.tab-label');
  if (label) label.textContent = trimmed === defaultLabel ? defaultLabel : trimmed;
}
function closeTabDock(id) {
  const wasActive = dockTabs.querySelector(`.dtab[data-tab="${id}"]`)?.classList.contains('active');
  dockTabs.querySelector(`.dtab[data-tab="${id}"]`)?.remove();
  ensurePane(id)?.remove();
  delete STATE.panels[id];
  delete STATE.tabNames[id];
  if (wasActive) activateTab('log');
}
function ensurePane(id) { return dockBody.querySelector(`[data-tab="${id}"]`); }

// ----- resizable divider -----
const divider = $('#divider');
const dock = $('.dock');
let dragging = false, startY = 0, startH = 0;
divider.addEventListener('mousedown', (e) => { dragging = true; startY = e.clientY; startH = dock.getBoundingClientRect().height; document.body.style.cursor = 'row-resize'; e.preventDefault(); });
window.addEventListener('mousemove', (e) => { if (!dragging) return; dock.style.height = Math.min(Math.max(startH + (startY - e.clientY), 140), window.innerHeight * 0.8) + 'px'; });
window.addEventListener('mouseup', () => { dragging = false; document.body.style.cursor = ''; });

// =====================================================================
// native Sliver console — shared by per-agent Interact tabs and the
// server-scope Sliver Console. Drives console.go's one-shot sliver-client
// invocation, so every native command works (getsystem, hashdump, armory…).
// =====================================================================
function pushConsoleRow(scroll, entry) {
  const atBottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 80;
  const row = el('div', 'cmd-row');
  const line = el('div', 'cmd-line');
  line.innerHTML = `<span class="dollar">sliver &rsaquo;</span><span class="txt">${esc(entry.cmd)}</span>` +
    (entry.pending ? '<span class="queued">running&hellip;</span>' : '');
  row.appendChild(line);
  if (entry.out) { const pre = el('pre', 'cmd-out'); pre.textContent = entry.out; row.appendChild(pre); }
  if (entry.err) { const pre = el('pre', 'cmd-out err'); pre.textContent = entry.err; row.appendChild(pre); }
  scroll.appendChild(row);
  if (atBottom) scroll.scrollTop = scroll.scrollHeight;
  return row;
}
async function runTermCommand(id, line, scroll) {
  line = line.trim();
  if (!line) return;
  const entry = { cmd: line, pending: true };
  const row = pushConsoleRow(scroll, entry);
  const words = line.split(/\s+/);
  const cmd = words[0].toLowerCase();
  if (cmd === 'clear') { scroll.innerHTML = ''; row.remove(); return; }
  // socks5 is intercepted instead of being sent to the native console. The
  // console runs a one-shot sliver-client that exits after each command, and a
  // socks proxy's listening socket lives in the client that started it — so
  // going down that path prints "Started SOCKS5" and then dies (see console.go).
  // Route it to the typed API that hosts the proxy on the bridge, so the
  // familiar command works and the proxy persists.
  if (cmd === 'socks5' || cmd === 'socks') { row.remove(); await runSocksCommand(id, line, scroll); return; }
  // Only a *bare* help/? gets this bridge-specific blurb. `help <command>` is a
  // real sliver-client command, and swallowing it here made the blurb's own
  // closing advice impossible to follow — it told you to type "help <command>"
  // and then answered with the same blurb again.
  if ((cmd === 'help' || cmd === '?') && words.length === 1) {
    row.remove();
    pushConsoleRow(scroll, {
      cmd: line,
      out: 'Native Sliver console — type any sliver-client command.\n\n' +
        'Scope matters: this tab runs at ' + (id ? 'agent' : 'server') + ' scope. ' +
        'Server commands (sessions, jobs, generate, armory…) work anywhere;\n' +
        'per-agent commands and armory aliases (ls, ps, getsystem, rubeus…)\n' +
        'only exist in an agent Terminal tab.\n\n' +
        'Common: sessions, beacons, use <id>, info, jobs, generate, ls, cd, ps,\n' +
        'download, upload, execute, execute-assembly, screenshot, kill, getsystem,\n' +
        'make-token, impersonate, procdump, hashdump, registry, execute-shellcode,\n' +
        'sideload, migrate, armory, profiles, loot, hosts, pivots.\n\n' +
        'socks5 is handled by the bridge (the native console cannot host a proxy):\n' +
        '  socks5                       list proxies this bridge hosts\n' +
        '  socks5 start [-H h] [-P p] [-u user]   default 127.0.0.1:1081\n' +
        '  socks5 stop -i <id>\n\n' +
        'Type "help <command>" or "<command> --help" for details.',
    });
    return;
  }
  try {
    const endpoint = id ? `/api/target/${id}/console` : '/api/console';
    const r = await api('POST', endpoint, { cmd: line });
    row.remove();
    let out = r.output || '(no output)';
    // Armory aliases and per-agent commands live in sliver-client's *agent*
    // menu, which it only enters via `use <id>`. The server-scope console never
    // issues that, so `help rubeus` there reports an unknown topic and prints
    // the server command list, with nothing to say why. Add the missing why.
    if (!id && /Unknown help topic/i.test(out)) {
      out += '\n\n[bridge] This is the server-scope console, so only server ' +
        'commands are in scope here. Armory aliases and per-agent commands ' +
        '(rubeus, seatbelt, ls, ps, getsystem, …) exist only once an agent is ' +
        "selected — run this from that agent's Terminal tab instead.";
    }
    pushConsoleRow(scroll, { cmd: line, out });
  } catch (err) {
    row.remove();
    pushConsoleRow(scroll, { cmd: line, err: err.message });
  }
}
// parseFlags reads `--flag value`, `--flag=value` and `-f value` the way the
// Sliver CLI's flags behave. Keys keep their case so -H and -h stay distinct.
function parseFlags(words) {
  const out = {};
  for (let i = 0; i < words.length; i++) {
    const m = /^--?([A-Za-z][\w-]*)(?:=(.*))?$/.exec(words[i]);
    if (!m) continue;
    let val = m[2];
    if (val === undefined) {
      const next = words[i + 1];
      val = next !== undefined && !next.startsWith('-') ? words[++i] : '';
    }
    out[m[1]] = val;
  }
  return out;
}
// runSocksCommand implements `socks5 start|stop|list` against the bridge-hosted
// proxy API, mirroring the CLI's flags (-H/--host, -P/--port, -u/--user,
// -i/--id) and its 127.0.0.1:1081 defaults.
async function runSocksCommand(id, line, scroll) {
  const words = line.split(/\s+/);
  const sub = (words[1] || 'list').toLowerCase();
  const f = parseFlags(words.slice(1));
  const pick = (...names) => { for (const n of names) if (f[n]) return f[n]; return ''; };
  const say = (out, err) => pushConsoleRow(scroll, { cmd: line, out, err });
  const refreshPane = () => { const p = ensurePane(id); if (p) loadSocks(id, p); };
  try {
    if (sub === 'start') {
      if (!id) { say(null, 'socks5 start needs a session — run it from a session tab, not the server console.'); return; }
      const m = await api('POST', `/api/target/${id}/socks`, {
        host: pick('host', 'H') || '127.0.0.1',
        port: pick('port', 'P') || '1081',
        user: pick('user', 'u'),
      });
      say(`Started SOCKS5 proxy ${m.BindAddr} (id ${m.ID})` +
        (m.Password ? `\nauth: ${m.Username}:${m.Password}` : '') +
        `\n\nHosted by the bridge, so it outlives this command and any page reload.` +
        `\nStop it with: socks5 stop -i ${m.ID}`);
      refreshPane();
      return;
    }
    if (sub === 'stop') {
      const sid = pick('id', 'i') || (words[2] && !words[2].startsWith('-') ? words[2] : '');
      if (!sid) { say(null, 'usage: socks5 stop -i <id>   (run "socks5" to list ids)'); return; }
      await api('DELETE', `/api/socks/${sid}`);
      say(`Stopped SOCKS5 proxy ${sid}`);
      refreshPane();
      return;
    }
    if (sub === 'list' || sub === '') {
      const all = await api('GET', '/api/socks') || [];
      if (!all.length) {
        say('No SOCKS5 proxies hosted by this bridge.\n\n' +
          'Note: proxies started from the sliver CLI live in that client process and\n' +
          'cannot be listed here — the server keeps no registry of them.\n\n' +
          'Start one with: socks5 start [-H host] [-P port] [-u user]');
        return;
      }
      const rows = all.map((s) => ` ${String(s.ID).padEnd(4)} ${s.BindAddr.padEnd(22)} ` +
        `${(s.Username ? s.Username + ':' + s.Password : 'no auth').padEnd(24)} ${s.SessionID.slice(0, 8)}`);
      say([' ID   Bind                   Auth                     Session', ...rows].join('\n'));
      return;
    }
    say(null, `unknown subcommand "${sub}" — use: socks5 [list] | socks5 start [-H host] [-P port] [-u user] | socks5 stop -i <id>`);
  } catch (e) { say(null, e.message); }
}
function completeCommand(input) {
  const text = input.value;
  const commands = ['sessions', 'beacons', 'use', 'info', 'jobs', 'generate', 'ls', 'cd', 'ps',
    'download', 'upload', 'execute', 'execute-assembly', 'screenshot', 'kill', 'getsystem',
    'make-token', 'impersonate', 'procdump', 'hashdump', 'registry', 'execute-shellcode',
    'sideload', 'migrate', 'armory', 'profiles', 'loot', 'hosts', 'pivots', 'socks5', 'help'];
  const words = text.split(/\s+/);
  const partial = words[words.length - 1];
  if (!partial) return;
  const matches = commands.filter(c => c.startsWith(partial.toLowerCase()));
  if (matches.length === 1) {
    words[words.length - 1] = matches[0];
    input.value = words.join(' ') + ' ';
  } else if (matches.length > 1) {
    words[words.length - 1] = partial.toUpperCase();
    input.value = words.join(' ');
  }
}
// ----- command history -----
// Recall survives a page reload: the list lives in localStorage keyed by agent
// id (the server console uses its own key), so an operator who refreshes mid-
// engagement keeps everything they've typed against that target. Only the
// commands are kept, not their output — transcripts can be megabytes and would
// blow the storage quota.
const HISTORY_MAX = 200;
const histKey = (id) => 'swg.hist.' + (id || '__server__');
function loadHistory(id) {
  try {
    const v = JSON.parse(localStorage.getItem(histKey(id)));
    return Array.isArray(v) ? v.slice(-HISTORY_MAX) : [];
  } catch { return []; }
}
function pushHistory(panel, id, line) {
  // Skip consecutive duplicates, the way a shell does.
  if (panel.history[panel.history.length - 1] !== line) panel.history.push(line);
  if (panel.history.length > HISTORY_MAX) panel.history = panel.history.slice(-HISTORY_MAX);
  panel.historyIdx = -1;
  try { localStorage.setItem(histKey(id), JSON.stringify(panel.history)); } catch {}
}
// wireTerminalKeys attaches up/down recall and tab completion to a command input.
function wireTerminalKeys(input, panel) {
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (panel.history.length === 0) return;
      if (panel.historyIdx === -1) panel.historyIdx = panel.history.length - 1;
      else if (panel.historyIdx > 0) panel.historyIdx--;
      input.value = panel.history[panel.historyIdx];
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (panel.historyIdx === -1) return;
      if (panel.historyIdx < panel.history.length - 1) {
        panel.historyIdx++;
        input.value = panel.history[panel.historyIdx];
      } else {
        panel.historyIdx = -1;
        input.value = '';
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      completeCommand(input);
    }
  });
}

// runInPanel drives a command from the context menu into an already-open
// agent console tab (Access > Elevate, etc.) as if the operator typed it.
function runInPanel(id, line) {
  const pane = ensurePane(id);
  if (!pane) return;
  const scroll = elIn(pane, 'term-scroll');
  runTermCommand(id, line, scroll);
}

// Server-scope console ("Sliver Console") — same mechanism, id=''.
function openScriptConsole() {
  const key = 'console';
  let pane = ensurePane(key);
  if (!pane) {
    pane = el('div', 'dpane consolepane');
    pane.dataset.tab = key;
    pane.innerHTML = `<div class="term-scroll"></div>
      <form class="term-input"><span class="dollar">sliver &rsaquo;</span>
        <input placeholder="server-scope command — armory, profiles, jobs, generate…" autocomplete="off">
        <button class="btn emerald sm" type="submit">run</button></form>`;
    const scroll = pane.querySelector('.term-scroll');
    const form = pane.querySelector('form');
    const input = pane.querySelector('input');
    STATE.panels[key] = { history: loadHistory(key), historyIdx: -1 };
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const line = input.value.trim();
      if (!line) return;
      pushHistory(STATE.panels[key], key, line);
      input.value = '';
      runTermCommand('', line, scroll);
    });
    wireTerminalKeys(input, STATE.panels[key]);
    dockBody.appendChild(pane);
    addTab(key, 'Sliver Console', null, true);
  }
  activateTab(key);
}

// =====================================================================
// per-agent panel (Interact tab): terminal / files / processes / network /
// screenshot / pivots / info — cloned from <template id="agent-panel-tpl">.
// =====================================================================
function openAgentConsole(id, subtab) {
  const rec = STATE.agents[id]; if (!rec) return;
  let pane = ensurePane(id);
  if (!pane) {
    pane = buildAgentPanel(id, rec);
    dockBody.appendChild(pane);
    const tabLabel = `${agentName(rec.a)}\\${rec.a.Username || '?'}`;
    addTab(id, tabLabel, rec.kind === 'beacon' ? 'var(--priv-med)' : (rec.kind === 'dead' ? 'var(--dead)' : 'var(--ok)'), true);
  }
  activateTab(id);
  switchSubtab(pane, id, subtab || (rec.kind === 'dead' ? 'info' : 'terminal'));
}

function buildAgentPanel(id, rec) {
  const tpl = $('#agent-panel-tpl');
  const frag = tpl.content.cloneNode(true);
  const root = frag.querySelector('[data-role="root"]');
  root.classList.add('dpane', 'consolepane');
  root.dataset.tab = id;
  root.style.display = '';
  const os = (rec.a.OS || '').toLowerCase();
  const cwd = os.includes('windows') ? 'C:\\' : '/';
  STATE.panels[id] = { cwd, history: loadHistory(id), historyIdx: -1 };

  $$('.subtab', root).forEach((t) => t.onclick = () => switchSubtab(root, id, t.dataset.sub));

  // ---- terminal ----
  const scroll = elIn(root, 'term-scroll');
  const form = elIn(root, 'term-form');
  const cmdInput = elIn(root, 'term-cmd');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const line = cmdInput.value.trim();
    if (!line) return;
    pushHistory(STATE.panels[id], id, line);
    cmdInput.value = '';
    runTermCommand(id, line, scroll);
  });
  wireTerminalKeys(cmdInput, STATE.panels[id]);

  // ---- files ----
  elIn(root, 'files-up').onclick = () => listDir(id, root, parentPath(STATE.panels[id].cwd));
  elIn(root, 'files-refresh').onclick = () => listDir(id, root, STATE.panels[id].cwd);
  elIn(root, 'files-mkdir').onclick = async () => {
    const name = prompt('New directory name:');
    if (!name) return;
    try { await api('POST', `/api/target/${id}/mkdir`, { path: joinPath(STATE.panels[id].cwd, name) }); listDir(id, root, STATE.panels[id].cwd); }
    catch (e) { alert(e.message); }
  };
  elIn(root, 'files-upload').addEventListener('change', async (ev) => {
    const file = ev.target.files[0];
    if (!file) return;
    try {
      const b64 = await readFileAsBase64(file);
      await api('POST', `/api/target/${id}/upload`, { path: joinPath(STATE.panels[id].cwd, file.name), data: b64 });
      listDir(id, root, STATE.panels[id].cwd);
    } catch (e) { alert(e.message); }
    ev.target.value = '';
  });

  // ---- screenshot ----
  elIn(root, 'shot-capture').onclick = () => captureScreenshot(id, root);

  // ---- pivots ----
  // allow-all is a named-pipe DACL option; hide it for tcp so it can't imply
  // it does something there.
  const pivotType = elIn(root, 'pivot-type');
  const syncPivotType = () => {
    elIn(root, 'pivot-allowall-field').style.display = pivotType.value === 'named-pipe' ? '' : 'none';
  };
  pivotType.onchange = syncPivotType;
  syncPivotType();

  elIn(root, 'pivot-start').onclick = async () => {
    const type = pivotType.value;
    const bind = elIn(root, 'pivot-bind').value.trim();
    if (!bind && type === 'named-pipe') { alert('Named pipe: specify a pipe name (e.g. \\\\.\\pipe\\MySliver)'); return; }
    const allowAll = elIn(root, 'pivot-allowall').checked;
    const msg = elIn(root, 'pivot-msg');
    msg.textContent = 'starting…';
    try {
      const pl = await api('POST', `/api/target/${id}/pivots`, { type, bind, allowAll });
      msg.textContent = 'listening on ' + (pl.BindAddress || bind);
      elIn(root, 'pivot-bind').value = '';
      loadPivots(id, root);
    } catch (e) { msg.textContent = 'error: ' + e.message; }
  };

  // ---- socks5 ----
  elIn(root, 'socks-start').onclick = async () => {
    const host = elIn(root, 'socks-host').value.trim();
    const port = elIn(root, 'socks-port').value.trim();
    const user = elIn(root, 'socks-user').value.trim();
    const msg = elIn(root, 'socks-msg');
    msg.textContent = 'starting…';
    try {
      const m = await api('POST', `/api/target/${id}/socks`, { host, port, user });
      msg.textContent = 'listening on ' + m.BindAddr + (m.Password ? ` (${m.Username}:${m.Password})` : '');
      loadSocks(id, root);
    } catch (e) { msg.textContent = 'error: ' + e.message; }
  };

  // ---- info ----
  elIn(root, 'info-rename').onclick = () => renameAgent(id, root);
  elIn(root, 'info-rename-reset').onclick = () => resetAgentName(id, root);
  elIn(root, 'cadence-save').onclick = () => saveCadence(id, root);
  elIn(root, 'info-kill').onclick = () => killAgent(id, root);
  elIn(root, 'info-remove').onclick = () => removeAgentFromInfo(id, root);

  return root;
}

function switchSubtab(root, id, name) {
  $$('.subtab', root).forEach((t) => t.classList.toggle('active', t.dataset.sub === name));
  $$('.subpane', root).forEach((p) => p.classList.toggle('active', p.dataset.pane === name));
  if (name === 'files') fileRefresh(id, root);
  else if (name === 'processes') loadProcs(id, root);
  else if (name === 'network') loadNet(id, root);
  else if (name === 'pivots') { loadPivots(id, root); loadSocks(id, root); }
  else if (name === 'info') renderInfo(id, root);
  else if (name === 'terminal') elIn(root, 'term-cmd').focus();
}

// ----- files -----
function fileRefresh(id, root) { listDir(id, root, STATE.panels[id].cwd); }
async function listDir(id, root, path) {
  const list = elIn(root, 'files-list');
  list.innerHTML = '<div class="side-empty">loading…</div>';
  try {
    const r = await api('POST', `/api/target/${id}/ls`, { path });
    STATE.panels[id].cwd = r.Path || path;
    elIn(root, 'files-path').value = STATE.panels[id].cwd;
    list.innerHTML = '';
    const files = (r.Files || []).filter((f) => f.Name !== '.').sort((a, b) => (b.IsDir - a.IsDir) || a.Name.localeCompare(b.Name));
    if (!files.length) { list.innerHTML = '<div class="side-empty">empty directory</div>'; return; }
    for (const f of files) {
      const row = el('div', 'file-row');
      const nm = el('span', 'fn ' + (f.IsDir ? 'dir' : 'file'), (f.IsDir ? '📁 ' : '📄 ') + f.Name);
      const full = joinPath(STATE.panels[id].cwd, f.Name);
      nm.onclick = f.IsDir ? () => listDir(id, root, full) : () => downloadFile(id, full, f.Name);
      row.appendChild(nm);
      row.appendChild(el('span', 'sz', f.IsDir ? '' : fmtSize(f.Size)));
      row.appendChild(el('span', 'md', f.Mode || ''));
      const acts = el('span', 'acts');
      if (!f.IsDir) {
        const dl = el('button', 'btn ghost sm', '⬇');
        dl.onclick = (e) => { e.stopPropagation(); downloadFile(id, full, f.Name); };
        acts.appendChild(dl);
      }
      const rm = el('button', 'btn ghost sm', '🗑');
      rm.onclick = (e) => { e.stopPropagation(); rmFile(id, root, full, f.IsDir); };
      acts.appendChild(rm);
      row.appendChild(acts);
      list.appendChild(row);
    }
  } catch (e) { list.innerHTML = `<div class="side-empty">${esc(e.message)}</div>`; }
}
async function downloadFile(id, path, name) {
  try {
    const r = await api('POST', `/api/target/${id}/download`, { path });
    if (!r.exists) { alert('file not found'); return; }
    saveBlob(b64ToBlob(r.data), name);
  } catch (e) { alert(e.message); }
}
async function rmFile(id, root, path, isDir) {
  if (!confirm('Delete ' + path + '?')) return;
  try { await api('POST', `/api/target/${id}/rm`, { path, recursive: isDir }); fileRefresh(id, root); }
  catch (e) { alert(e.message); }
}

// ----- processes -----
async function loadProcs(id, root) {
  const body = elIn(root, 'procs-body');
  body.innerHTML = '<tr><td colspan="5" class="empty">loading…</td></tr>';
  try {
    const r = await api('GET', `/api/target/${id}/ps`);
    body.innerHTML = '';
    const procs = (r.Processes || []).slice().sort((a, b) => a.Pid - b.Pid);
    if (!procs.length) { body.innerHTML = '<tr><td colspan="5" class="empty">no processes</td></tr>'; return; }
    for (const p of procs) {
      const tr = el('tr');
      tr.innerHTML = `<td>${p.Pid}</td><td>${p.Ppid}</td><td>${esc(p.Owner)}</td><td>${esc(p.Architecture)}</td><td>${esc(p.Executable)}</td>`;
      body.appendChild(tr);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="5" class="empty">${esc(e.message)}</td></tr>`; }
}

// ----- network -----
async function loadNet(id, root) {
  const out = elIn(root, 'net-out');
  out.textContent = 'loading…';
  try {
    const [ifc, ns] = await Promise.all([
      api('GET', `/api/target/${id}/ifconfig`).catch(() => null),
      api('GET', `/api/target/${id}/netstat`).catch(() => null),
    ]);
    let s = '';
    if (ifc && ifc.NetInterfaces) {
      s += '── Interfaces ──\n';
      for (const i of ifc.NetInterfaces) s += `${i.Name}  ${(i.IPAddresses || []).join(', ')}\n`;
    }
    if (ns && ns.Entries) {
      s += '\n── Connections ──\n';
      for (const e of ns.Entries) s += `${e.Protocol}\t${e.LocalAddr?.Ip}:${e.LocalAddr?.Port}\t${e.RemoteAddr?.Ip}:${e.RemoteAddr?.Port}\t${e.SkState}\n`;
    }
    out.textContent = s || 'no data';
  } catch (e) { out.textContent = e.message; }
}

// ----- screenshot (dedicated typed endpoint — the native console can't
// stream binary image data back through a text transcript) -----
async function captureScreenshot(id, root) {
  const wrap = elIn(root, 'shot-img');
  wrap.textContent = 'capturing…';
  try {
    const r = await api('GET', `/api/target/${id}/screenshot`);
    if (!r.data) { wrap.textContent = 'no image data'; return; }
    wrap.innerHTML = `<img src="data:image/png;base64,${r.data}">`;
  } catch (e) { wrap.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}

// ----- pivots (per-session) -----
async function loadPivots(id, root) {
  const body = elIn(root, 'pivot-body');
  body.innerHTML = '<tr><td colspan="5" class="muted">loading…</td></tr>';
  try {
    const pivots = await api('GET', `/api/target/${id}/pivots`);
    if (!pivots || !pivots.length) { body.innerHTML = '<tr><td colspan="5" class="muted">no active pivot listeners</td></tr>'; return; }
    body.innerHTML = '';
    for (const p of pivots) {
      const row = el('tr');
      row.innerHTML =
        `<td class="mono">${p.ID}</td><td>${p.Type === 0 ? 'TCP' : p.Type === 2 ? 'Named Pipe' : 'UDP'}</td>` +
        `<td class="mono">${p.BindAddress || '—'}</td><td>${(p.Pivots || []).length} downstream</td><td></td>`;
      const stop = el('button', 'btn danger xs', 'stop');
      stop.onclick = async () => {
        if (!confirm(`Stop pivot ${p.ID}?`)) return;
        try { await api('DELETE', `/api/target/${id}/pivots/${p.ID}`); loadPivots(id, root); } catch (e) { alert(e.message); }
      };
      row.lastElementChild.appendChild(stop);
      body.appendChild(row);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="5" class="err">${esc(e.message)}</td></tr>`; }
}

// ----- socks5 (hosted by the bridge, filtered to this session) -----
async function loadSocks(id, root) {
  const body = elIn(root, 'socks-body');
  body.innerHTML = '<tr><td colspan="5" class="muted">loading…</td></tr>';
  try {
    const all = await api('GET', '/api/socks');
    const mine = (all || []).filter((s) => s.SessionID === id);
    if (!mine.length) { body.innerHTML = '<tr><td colspan="5" class="muted">no active socks5 proxies</td></tr>'; return; }
    body.innerHTML = '';
    for (const s of mine) {
      const row = el('tr');
      row.innerHTML =
        `<td class="mono">${s.ID}</td><td class="mono">${esc(s.BindAddr)}</td>` +
        `<td class="mono">${s.Username ? esc(s.Username + ':' + s.Password) : 'none'}</td>` +
        `<td class="mono">${esc(s.SessionID.slice(0, 8))}</td><td></td>`;
      const stop = el('button', 'btn danger xs', 'stop');
      stop.onclick = async () => {
        if (!confirm(`Stop socks5 proxy ${s.ID} (${s.BindAddr})?`)) return;
        try { await api('DELETE', `/api/socks/${s.ID}`); loadSocks(id, root); } catch (e) { alert(e.message); }
      };
      row.lastElementChild.appendChild(stop);
      body.appendChild(row);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="5" class="err">${esc(e.message)}</td></tr>`; }
}

// ----- info: metadata, rename, beacon cadence, kill/remove -----
function renderInfo(id, root) {
  const rec = STATE.agents[id]; if (!rec) return;
  const a = rec.a;
  const rows = [
    ['type', rec.kind], ['agent id', a.ID, true], ['name', a.Name], ['user', a.Username],
    ['hostname', a.Hostname], ['domain', domainOf(a)], ['os / arch', `${a.OS}/${a.Arch}`],
    ['remote address', remoteAddr(a), true], ['transport', a.Transport], ['pid', a.PID],
    ['version', a.Version], ['last check-in', ago(a.LastCheckin)],
  ];
  const dl = elIn(root, 'info-dl');
  dl.innerHTML = '';
  for (const [k, v, mono] of rows) {
    const div = el('div');
    div.appendChild(el('dt', null, k));
    div.appendChild(el('dd', mono ? 'mono' : null, v == null || v === '' ? '—' : String(v)));
    dl.appendChild(div);
  }
  const nameInput = elIn(root, 'info-name');
  if (nameInput.dataset.shownFor !== a.ID) {
    nameInput.dataset.shownFor = a.ID;
    nameInput.value = RENAMED[a.ID] ? (a.Name || '') : '';
    elIn(root, 'info-rename-msg').textContent = '';
  }
  nameInput.placeholder = hostLabel(a);
  elIn(root, 'info-rename-reset').style.display = RENAMED[a.ID] ? '' : 'none';

  const removable = rec.isBeacon || rec.kind === 'dead';
  elIn(root, 'info-remove').style.display = removable ? '' : 'none';

  const cad = elIn(root, 'info-cadence');
  if (rec.kind === 'beacon') {
    const secs = (ns) => Math.max(0, Math.round((ns || 0) / 1e9));
    const iv = secs(a.Interval), jt = secs(a.Jitter);
    elIn(root, 'cadence-interval').value = iv;
    elIn(root, 'cadence-jitter').value = jt;
    elIn(root, 'cadence-current').innerHTML = `Currently <b>${iv}s</b> sleep, <b>${jt}s</b> jitter &middot; next check-in in ${iv}&ndash;${iv + jt}s.`;
    elIn(root, 'cadence-msg').textContent = '';
    cad.style.display = '';
  } else cad.style.display = 'none';
}
// renameAgentDirect is the graph/table context-menu fast path — a plain
// prompt(), for when the operator doesn't want to open the full Interact tab
// just to rename something. Same validation and API call as the Info tab's
// rename form.
async function renameAgentDirect(id) {
  const rec = STATE.agents[id]; if (!rec) return;
  const name = prompt('Rename agent:', agentName(rec.a));
  if (!name || !name.trim()) return;
  const trimmed = name.trim();
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(trimmed) || /^\.\.?/.test(trimmed)) { alert('letters, digits, .-_ only (max 32)'); return; }
  try {
    await api('POST', `/api/target/${id}/rename`, { name: trimmed });
    markRenamed(id, true);
    updateTabLabel(id, rec);
    loadAgents();
  } catch (e) { alert(e.message); }
}
async function renameAgent(id, root) {
  const rec = STATE.agents[id]; if (!rec) return;
  const msg = elIn(root, 'info-rename-msg');
  const name = elIn(root, 'info-name').value.trim();
  if (!name) { msg.className = 'err'; msg.textContent = ' enter a name (or use reset)'; return; }
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(name) || /^\.\.?/.test(name)) { msg.className = 'err'; msg.textContent = ' letters, digits, .-_ only (max 32)'; return; }
  msg.className = 'muted mono'; msg.textContent = ' renaming…';
  try {
    await api('POST', `/api/target/${id}/rename`, { name });
    markRenamed(id, true);
    msg.className = 'ok'; msg.textContent = ' renamed';
    updateTabLabel(id, rec);
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
}
async function resetAgentName(id, root) {
  const rec = STATE.agents[id]; if (!rec) return;
  const host = rec.a.Hostname;
  const msg = elIn(root, 'info-rename-msg');
  const validHost = host && /^[A-Za-z0-9._-]{1,32}$/.test(host) && !/^\.\.?/.test(host);
  msg.className = 'muted mono'; msg.textContent = ' resetting…';
  try {
    if (validHost) await api('POST', `/api/target/${id}/rename`, { name: host });
    markRenamed(id, false);
    elIn(root, 'info-name').value = '';
    msg.className = 'ok'; msg.textContent = ' reset to hostname';
    updateTabLabel(id, rec);
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
}
function updateTabLabel(id, rec) {
  const tab = dockTabs.querySelector(`.dtab[data-tab="${id}"] .tab-label`);
  if (tab) tab.textContent = agentName(rec.a);
}
async function saveCadence(id, root) {
  const interval = parseInt(elIn(root, 'cadence-interval').value, 10);
  const jitter = parseInt(elIn(root, 'cadence-jitter').value, 10);
  const msg = elIn(root, 'cadence-msg');
  if (!(interval >= 1)) { msg.className = 'err'; msg.textContent = 'sleep must be ≥ 1s'; return; }
  if (!(jitter >= 0)) { msg.className = 'err'; msg.textContent = 'jitter must be ≥ 0s'; return; }
  msg.className = 'muted mono'; msg.textContent = 'saving…';
  try {
    await api('POST', `/api/target/${id}/reconfigure`, { interval, jitter });
    msg.className = 'ok'; msg.textContent = 'saved — applies on next check-in';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
}
async function killAgent(id, root) {
  const rec = STATE.agents[id]; if (!rec) return;
  if (!confirm(`Kill agent ${agentName(rec.a)}?`)) return;
  const msg = elIn(root, 'info-kill-msg');
  msg.className = 'muted mono'; msg.textContent = ' killing…';
  try {
    await api('POST', `/api/target/${id}/kill`);
    msg.className = 'ok'; msg.textContent = ' killed';
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
}
async function removeAgentFromInfo(id, root) {
  const rec = STATE.agents[id]; if (!rec) return;
  if (!confirm(`Remove ${agentName(rec.a)} from the console? (does not signal the implant)`)) return;
  const msg = elIn(root, 'info-kill-msg');
  msg.className = 'muted mono'; msg.textContent = ' removing…';
  try {
    await removeAgentRecord(id, rec);
    msg.className = 'ok'; msg.textContent = ' removed';
    closeTabDock(id);
    loadAgents();
  } catch (e) { msg.className = 'err'; msg.textContent = ' ' + e.message; }
}

// =====================================================================
// utility tabs: Event Log / Sliver Console / Proxy Pivots / Profiles /
// Implants / Manage Listeners / Help
// =====================================================================
function openUtilTab(key) {
  if (key === 'console') { openScriptConsole(); return; }
  let pane = ensurePane(key);
  if (!pane) {
    const tpl = $(`#util-${key}-tpl`);
    const label = { log: 'Event Log', jobs: 'Listeners', stagelisteners: 'Stage Listeners', profiles: 'Profiles', implants: 'Implants', pivotgraph: 'Proxy Pivots', help: 'Help' }[key];
    if (tpl) {
      const frag = tpl.content.cloneNode(true);
      pane = frag.firstElementChild;
    } else {
      pane = el('div', 'utilpane');
    }
    pane.classList.add('dpane');
    pane.dataset.tab = key;
    dockBody.appendChild(pane);
    addTab(key, label, null, key !== 'log');
    if (key === 'jobs') initJobsPane(pane);
    else if (key === 'stagelisteners') initStageListenersPane(pane);
    else if (key === 'profiles') initProfilesPane(pane);
    else if (key === 'implants') initImplantsPane(pane);
    else if (key === 'pivotgraph') initPivotGraphPane(pane);
  }
  activateTab(key);
  if (key === 'jobs') loadJobs(pane);
  else if (key === 'stagelisteners') loadStageListeners(pane);
  else if (key === 'profiles') loadProfiles(pane);
  else if (key === 'implants') loadImplants(pane);
  else if (key === 'pivotgraph') loadPivotGraphTable(pane);
}

// ----- Event Log (pinned) -----
let LOG_PANE;
function initEventLog() {
  LOG_PANE = el('div', 'dpane logpane active');
  LOG_PANE.dataset.tab = 'log';
  dockBody.appendChild(LOG_PANE);
  addTab('log', 'Event Log', null, false);
}
function logEvent(ev) {
  let cls = '';
  if (/connected/i.test(ev.type)) cls = 'connect';
  else if (/disconnected/i.test(ev.type)) cls = 'disconnect';
  else if (/job/i.test(ev.type)) cls = 'job';
  const who = ev.session ? ` ${ev.session.Name}@${ev.session.Hostname}` : ev.job ? ` ${ev.job.Name}:${ev.job.Port}` : '';
  const div = el('div', 'logline ' + cls);
  div.innerHTML = `<span class="t">${new Date().toLocaleTimeString()}</span><span>${esc(ev.type)}${esc(who)}</span>`;
  LOG_PANE.appendChild(div);
  LOG_PANE.scrollTop = LOG_PANE.scrollHeight;
  while (LOG_PANE.children.length > 300) LOG_PANE.removeChild(LOG_PANE.firstChild);
}
function startEvents() {
  const es = new EventSource('/api/events');
  es.onmessage = (m) => {
    let ev; try { ev = JSON.parse(m.data); } catch { return; }
    logEvent(ev);
    if (ev.session || ev.job || /session|beacon|connected|disconnected/i.test(ev.type)) loadAgents();
    if (/job/i.test(ev.type)) { const p = ensurePane('jobs'); if (p) loadJobs(p); }
  };
  es.onerror = () => {};
}

// ----- Manage Listeners (jobs + stale detection) -----
function initJobsPane(pane) {
  // no persistent wiring needed beyond load; buttons are built per-row
}
async function loadJobs(pane) {
  const body = elIn(pane, 'jobs-body');
  try {
    const jobs = await api('GET', '/api/jobs');
    body.innerHTML = '';
    if (!jobs || !jobs.length) { body.innerHTML = '<tr><td colspan="6" class="empty">no active listeners</td></tr>'; }
    else {
      for (const j of jobs) {
        const tr = el('tr');
        tr.innerHTML = `<td>${j.ID}</td><td>${esc(j.Name)}</td><td>${esc(j.Protocol)}</td><td>${j.Port}</td><td>${esc(j.Description)}</td><td></td>`;
        if (['mtls', 'http', 'https'].includes(j.Name)) {
          const editBtn = el('button', 'btn ghost sm', 'edit');
          editBtn.style.marginRight = '4px';
          editBtn.onclick = () => openEditListener(j);
          tr.lastElementChild.appendChild(editBtn);
        }
        const stop = el('button', 'btn danger sm', 'stop');
        stop.onclick = async () => { try { await api('DELETE', '/api/jobs/' + j.ID); loadJobs(pane); } catch (e) { alert(e.message); } };
        tr.lastElementChild.appendChild(stop);
        body.appendChild(tr);
      }
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="6" class="empty">${esc(e.message)}</td></tr>`; }
  loadStale(pane);
}
async function loadStale(pane) {
  const section = elIn(pane, 'stale-section');
  const body = elIn(pane, 'stale-body');
  let stale;
  try { stale = await api('GET', '/api/jobs/stale'); } catch { section.style.display = 'none'; return; }
  if (!stale || !stale.length) { section.style.display = 'none'; return; }
  section.style.display = '';
  elIn(pane, 'stale-count').textContent = stale.length;
  body.innerHTML = '';
  for (const s of stale) {
    const tr = el('tr');
    tr.innerHTML = `<td>${s.job_id}</td><td>${esc(s.type)}</td><td class="mono">${esc(s.host || '—')}</td><td>${s.port}</td><td></td>`;
    const rm = el('button', 'btn danger sm', 'remove');
    rm.onclick = async () => {
      if (!confirm(`Remove stale listener record (job ${s.job_id})?`)) return;
      try { await api('DELETE', '/api/jobs/stale/' + s.job_id); loadJobs(pane); } catch (e) { alert(e.message); }
    };
    tr.lastElementChild.appendChild(rm);
    body.appendChild(tr);
  }
}

// ----- Stage Listeners -----
function initStageListenersPane(pane) {
  const startBtn = elIn(pane, 'sl-start');
  const msg = elIn(pane, 'sl-msg');
  startBtn.onclick = async () => {
    const url = elIn(pane, 'sl-url').value.trim();
    const profile = elIn(pane, 'sl-profile').value;
    const prependSize = elIn(pane, 'sl-prepend-size').checked;
    if (!url) { msg.className = 'err'; msg.textContent = 'enter URL'; return; }
    if (!profile) { msg.className = 'err'; msg.textContent = 'select profile'; return; }
    msg.className = 'muted'; msg.textContent = 'starting…';
    try {
      await api('POST', '/api/stage-listeners', { url, profile, prependSize });
      msg.className = 'ok'; msg.textContent = 'started';
      elIn(pane, 'sl-url').value = '';
      setTimeout(() => { msg.textContent = ''; loadStageListeners(pane); }, 800);
    } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  };
  elIn(pane, 'sl-profile').addEventListener('change', () => syncStagePrependSize(pane));
  refreshStageProfiles(pane);
}
async function loadStageListeners(pane) {
  const body = elIn(pane, 'sl-body');
  try {
    const listeners = await api('GET', '/api/stage-listeners');
    body.innerHTML = '';
    if (!listeners || !listeners.length) { body.innerHTML = '<tr><td colspan="4" class="empty">no active stage listeners</td></tr>'; }
    else {
      for (const l of listeners) {
        const tr = el('tr');
        tr.innerHTML = `<td>${l.JobID}</td><td class="mono">${esc(l.URL)}</td><td>${esc(l.Profile)}</td><td></td>`;
        const stop = el('button', 'btn danger sm', 'stop');
        stop.onclick = async () => { try { await api('DELETE', '/api/jobs/' + l.JobID); loadStageListeners(pane); } catch (e) { alert(e.message); } };
        tr.lastElementChild.appendChild(stop);
        body.appendChild(tr);
      }
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="4" class="empty">${esc(e.message)}</td></tr>`; }
}
async function refreshStageProfiles(pane) {
  const sel = elIn(pane, 'sl-profile');
  try {
    const profiles = await api('GET', '/api/profiles');
    sel.innerHTML = '';
    if (!profiles || !profiles.length) sel.appendChild(new Option('— no profiles —', ''));
    else for (const p of profiles) {
      const opt = new Option(p.Name, p.Name);
      // Carried so selecting a profile can tick the framing it was saved with —
      // prepend-size has to match the stager or the stage never runs.
      opt.dataset.prependSize = p.PrependSize ? '1' : '';
      sel.appendChild(opt);
    }
    syncStagePrependSize(pane);
  } catch { sel.innerHTML = ''; sel.appendChild(new Option('— error loading profiles —', '')); }
}
// Mirror the selected profile's saved prepend-size onto the checkbox. The
// operator can still override it for this one listener; the box is the value
// that gets sent, so what they see is what runs.
function syncStagePrependSize(pane) {
  const sel = elIn(pane, 'sl-profile');
  const opt = sel.selectedOptions[0];
  elIn(pane, 'sl-prepend-size').checked = !!(opt && opt.dataset.prependSize);
}

// ----- Profiles (Payloads > Implant Profiles) -----
const OUTPUT_FORMAT_NAME = { 0: 'shared', 1: 'shellcode', 2: 'exe', 3: 'service' };
function fmtC2(cfg) {
  if (!cfg) return '—';
  const urls = (cfg.C2 || []).map((c) => c.URL);
  return urls.length ? urls.join(', ') : '—';
}
// Condense a profile's build options into one table cell. Only non-default
// settings are listed, so the column stays empty for a plain profile instead of
// repeating the same six "off"s on every row.
const SHELLCODE_ENCODER_NAME = { 1: 'shikata_ga_nai', 2: 'xor', 3: 'xor_dynamic' };
function fmtProfileOpts(cfg, p) {
  const on = [];
  // Bridge-side, not part of ImplantConfig — listed first because it decides
  // whether a staged payload runs at all.
  if (p && p.PrependSize) on.push('prepend-size');
  if (cfg.Debug) on.push('debug');
  if (cfg.Evasion) on.push('evasion');
  if (cfg.ObfuscateSymbols) on.push('obfuscated');
  if (cfg.NetGoEnabled) on.push('netgo');
  if (cfg.RunAtLoad) on.push('run-at-load');
  if (cfg.LimitDomainJoined) on.push('domain-joined');
  for (const [label, v] of [['host', cfg.LimitHostname], ['user', cfg.LimitUsername],
    ['file', cfg.LimitFileExists], ['locale', cfg.LimitLocale], ['before', cfg.LimitDatetime]]) {
    if (v) on.push(`${label}=${v}`);
  }
  if (cfg.ShellcodeEncoder) on.push(SHELLCODE_ENCODER_NAME[cfg.ShellcodeEncoder] || 'encoded');
  const sc = cfg.ShellcodeConfig;
  // Compress is 1=none / 2=aPLib on the wire, so only 2 is worth reporting.
  if (sc && sc.Compress === 2) on.push('compressed');
  if (sc && sc.Entropy > 1) on.push(`entropy=${sc.Entropy}`);
  return on.join(', ');
}
function initProfilesPane(pane) {
  elIn(pane, 'prof-new').onclick = () => openProfileModal();
}
async function loadProfiles(pane) {
  const body = elIn(pane, 'profiles-body');
  body.innerHTML = '<tr><td colspan="7" class="muted">loading…</td></tr>';
  try {
    const profiles = await api('GET', '/api/profiles');
    if (!profiles || !profiles.length) { body.innerHTML = '<tr><td colspan="7" class="muted">no saved profiles</td></tr>'; }
    else {
      body.innerHTML = '';
      for (const p of profiles) {
        const cfg = p.Config || {};
        const tr = el('tr');
        tr.innerHTML =
          `<td class="mono">${esc(p.Name)}</td><td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td>` +
          `<td>${esc(OUTPUT_FORMAT_NAME[cfg.Format] ?? cfg.Format)}</td><td>${cfg.IsBeacon ? 'beacon' : 'session'}</td>` +
          `<td class="mono" style="font-size:12px">${esc(fmtC2(cfg))}</td>` +
          `<td class="mono muted" style="font-size:11.5px">${esc(fmtProfileOpts(cfg, p))}</td><td></td>`;
        const ed = el('button', 'btn sm', 'edit');
        ed.style.marginRight = '6px';
        ed.onclick = () => openProfileModal(p);
        const rm = el('button', 'btn danger sm', 'delete');
        rm.onclick = async () => {
          if (!confirm(`Delete profile "${p.Name}"?`)) return;
          try { await api('DELETE', '/api/profiles/' + encodeURIComponent(p.Name)); loadProfiles(pane); } catch (e) { alert(e.message); }
        };
        tr.lastElementChild.appendChild(ed);
        tr.lastElementChild.appendChild(rm);
        body.appendChild(tr);
      }
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="7" class="err">${esc(e.message)}</td></tr>`; }
}

// ----- Implants (Payloads > Implant Builds) -----
async function deleteSelectedImplants() {
  const tbody = document.querySelector('[data-el="implants-body"]');
  if (!tbody) return;
  const cbs = Array.from(tbody.querySelectorAll('input[type="checkbox"]:checked'));
  const toDelete = cbs.map(cb => cb.dataset.name);
  if (!toDelete.length) return;
  if (!confirm(`Delete ${toDelete.length} implant(s)?`)) return;
  for (const name of toDelete) {
    try { await api('DELETE', '/api/implants/' + encodeURIComponent(name)); } catch (e) { console.error(e); }
  }
  const pane = document.querySelector('.utilpane[data-tab="implants"]');
  if (pane) await loadImplants(pane);
}
function initImplantsPane(pane) {
  const selectAllCb = pane.querySelector('#implants-select-all');
  if (selectAllCb) {
    selectAllCb.onchange = () => {
      const tbody = pane.querySelector('[data-el="implants-body"]');
      const cbs = tbody ? tbody.querySelectorAll('input[type="checkbox"]') : [];
      cbs.forEach(cb => { cb.checked = selectAllCb.checked; });
      updateImplantCount();
    };
  }
}
async function loadImplants(pane) {
  const body = elIn(pane, 'implants-body');
  body.innerHTML = '<tr><td colspan="8" class="muted">loading…</td></tr>';
  try {
    const builds = await api('GET', '/api/implants');
    if (!builds || !builds.length) { body.innerHTML = '<tr><td colspan="8" class="muted">no implants built yet</td></tr>'; return; }
    body.innerHTML = '';
    for (const b of builds) {
      const cfg = b.Config || {};
      const tr = el('tr');
      tr.innerHTML =
        `<td style="width:20px"><input type="checkbox" data-name="${esc(b.Name)}" style="cursor:pointer"></td>` +
        `<td class="mono">${esc(b.Name)}</td><td>${esc(cfg.GOOS)}/${esc(cfg.GOARCH)}</td>` +
        `<td>${esc(OUTPUT_FORMAT_NAME[cfg.Format] ?? cfg.Format)}</td><td>${cfg.IsBeacon ? 'beacon' : 'session'}</td>` +
        `<td class="mono" style="font-size:12px">${esc(fmtC2(cfg))}</td><td>${b.Staged ? 'yes' : 'no'}</td><td></td>`;
      const cb = tr.querySelector('input[type="checkbox"]');
      cb.onchange = updateImplantCount;
      const rm = el('button', 'btn danger sm', 'delete');
      rm.onclick = async () => {
        if (!confirm(`Delete implant "${b.Name}"?`)) return;
        try { await api('DELETE', '/api/implants/' + encodeURIComponent(b.Name)); loadImplants(pane); } catch (e) { alert(e.message); }
      };
      tr.lastElementChild.appendChild(rm);
      body.appendChild(tr);
    }
    updateImplantCount();
  } catch (e) { body.innerHTML = `<tr><td colspan="8" class="err">${esc(e.message)}</td></tr>`; }
}
function updateImplantCount() {
  const tbody = document.querySelector('[data-el="implants-body"]');
  const cbs = tbody ? Array.from(tbody.querySelectorAll('input[type="checkbox"]:checked')) : [];
  const count = cbs.length;
  const countSpan = $('#implants-count');
  const deleteBtn = $('#implants-delete-btn');
  if (countSpan) countSpan.textContent = count ? `${count} selected` : '';
  if (deleteBtn) deleteBtn.style.display = count ? 'block' : 'none';
}

// ----- Proxy Pivots (View > Proxy Pivots — server-wide pivot graph, table form) -----
function initPivotGraphPane() {}
async function loadPivotGraphTable(pane) {
  const body = elIn(pane, 'pivot-graph-body');
  body.innerHTML = '<tr><td colspan="3" class="muted">loading…</td></tr>';
  try {
    const graph = await api('GET', '/api/pivots');
    if (!graph || !graph.Children || !graph.Children.length) { body.innerHTML = '<tr><td colspan="3" class="muted">no pivots established</td></tr>'; return; }
    body.innerHTML = '';
    for (const child of graph.Children) {
      const row = el('tr');
      row.innerHTML = `<td class="mono">${child.ID || '—'}</td><td>${esc(child.Hostname || '—')}</td><td>${(child.Children || []).length}</td>`;
      body.appendChild(row);
    }
  } catch (e) { body.innerHTML = `<tr><td colspan="3" class="err">${esc(e.message)}</td></tr>`; }
}

// =====================================================================
// modal dialogs: About, Start Listener, Generate Payload
// =====================================================================
const veil = $('#modalveil');
const modals = { listener: $('#modalListener'), generate: $('#modalGenerate'), profile: $('#modalProfile'), about: $('#modalAbout') };
function openModal(which) {
  Object.values(modals).forEach((m) => m.style.display = 'none');
  modals[which].style.display = 'flex';
  modals[which].style.flexDirection = 'column';
  veil.style.display = 'flex';
  if (which === 'generate') { refreshGenListenerList(); refreshGenProfileList(); }
}
function closeModal() { veil.style.display = 'none'; }
veil.addEventListener('click', (e) => { if (e.target === veil) closeModal(); });
$$('[data-close]').forEach((b) => b.onclick = closeModal);
window.addEventListener('keydown', (e) => { if (e.key === 'Escape' && veil.style.display !== 'none') closeModal(); });

async function openAbout() {
  const body = $('#aboutBody');
  body.innerHTML = '<span class="muted mono">loading…</span>';
  openModal('about');
  try {
    const c = await api('GET', '/api/config');
    body.innerHTML = `<div class="hostport"><span class="lbl" style="width:90px">Operator</span><span class="mono">${esc(c.operator)}</span></div>
      <div class="hostport"><span class="lbl" style="width:90px">Server</span><span class="mono">${esc(c.server)}</span></div>`;
  } catch (e) { body.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}

// ----- Start / Edit Listener -----
// Sliver has no "update a running listener" RPC, so editing means: stop the
// existing job, then start a new one with the edited settings. HTTP(S) jobs
// don't report their bind host back (only mTLS's Description embeds it), so
// that field can't always be pre-filled — flagged to the operator via a note.
let EDIT_JOB_ID = null;
function resetListenerModal() {
  EDIT_JOB_ID = null;
  $('#mlHead').textContent = 'Start Listener';
  $('#mlSave').textContent = 'Start';
  $('#mlEditNote').style.display = 'none';
}
function openEditListener(job) {
  EDIT_JOB_ID = job.ID;
  $('#mlType').value = job.Name;
  $('#mlPort').value = job.Port;
  $('#mlDomain').value = (job.Domains && job.Domains[0]) || '';
  let host = '';
  if (job.Name === 'mtls') {
    const m = (job.Description || '').match(/mutual tls listener (.+):\d+$/);
    if (m) host = m[1];
  }
  const note = $('#mlEditNote');
  if (host) {
    $('#mlHost').value = host;
    note.style.display = 'none';
  } else {
    note.style.display = '';
    note.innerHTML = `Editing job <b>${job.ID}</b>. Sliver doesn't report the bind host for HTTP(S) jobs — verify or re-enter it below before saving.`;
  }
  $('#mlHead').textContent = `Edit Listener (job ${job.ID})`;
  $('#mlSave').textContent = 'Save (restarts listener)';
  updateBindWarning();
  openModal('listener');
}
$('#tbListener').onclick = () => { resetListenerModal(); openModal('listener'); };
$('#mlSave').onclick = async () => {
  const type = $('#mlType').value, host = $('#mlHost').value.trim(), port = parseInt($('#mlPort').value, 10) || 0, domain = $('#mlDomain').value.trim();
  const msg = $('#mlMsg');
  if (isVPNBind(host) && !confirm(`Bind to ${host} (${ifaceForIP(host)})? This VPN/tunnel interface may not be up at boot and could strand this port. Continue?`)) return;
  if (EDIT_JOB_ID != null && !confirm(`This stops job ${EDIT_JOB_ID} and starts a new listener with these settings — implants already using the old one will lose their connection until they reconnect to the new job. Continue?`)) return;
  const editing = EDIT_JOB_ID;
  msg.className = 'muted mono'; msg.textContent = editing != null ? 'restarting…' : 'starting…';
  try {
    if (editing != null) await api('DELETE', '/api/jobs/' + editing);
    if (type === 'mtls') await api('POST', '/api/jobs/mtls', { host, port: port || 8888 });
    else await api('POST', '/api/jobs/http', { host, domain, port: port || (type === 'https' ? 443 : 80), secure: type === 'https' });
    msg.className = 'ok'; msg.textContent = editing != null ? 'listener replaced' : 'started';
    resetListenerModal();
    const p = ensurePane('jobs'); if (p) loadJobs(p);
    setTimeout(closeModal, 700);
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
};

// ----- Generate Payload -----
// Mirrors Cobalt Strike's Generate Payload dialog: pick a *Listener* instead
// of typing C2 details by hand. mTLS jobs report their bind host (parsed from
// the job Description); HTTP(S) jobs don't expose one at all, so that field
// is left editable rather than silently wrong. Named Pipe has no backing job
// (it targets a pivot, not a server-wide listener), so it stays a manual
// pipe-path entry, offered as a sentinel option in the same dropdown.
function updateGenListenerFields() {
  const isPipe = $('#mgListener').value === '__namedpipe__';
  $('#mgC2HostPortRow').style.display = isPipe ? 'none' : '';
  $('#mgPipeField').style.display = isPipe ? '' : 'none';
}

// Sliver's output formats are not uniform across targets, so the Output and
// Architecture lists are rebuilt whenever the OS changes rather than being a
// fixed windows-flavoured list:
//   - `service` is a Windows *service* binary (IsService); the server builds it
//     with the plain executable path, so on linux/darwin it would silently
//     produce an ordinary binary mislabelled as a service.
//   - shellcode is implemented per-OS with narrower arch support than the OS
//     itself has (server/generate/binaries.go: SliverShellcode) — windows
//     amd64/386, linux amd64/arm64, darwin arm64 — so it is filtered by arch
//     as well as by OS.
const GEN_FORMATS = {
  windows: [
    ['exe', 'Windows EXE (.exe)'],
    ['service', 'Windows Service EXE'],
    ['shared', 'Windows DLL (.dll)'],
    ['shellcode', 'Shellcode (.bin)'],
  ],
  linux: [
    ['exe', 'Linux executable (ELF)'],
    ['shared', 'Linux shared library (.so)'],
    ['shellcode', 'Shellcode (.bin)'],
  ],
  darwin: [
    ['exe', 'macOS executable (Mach-O)'],
    ['shared', 'macOS dynamic library (.dylib)'],
    ['shellcode', 'Shellcode (.bin)'],
  ],
};
// Architectures Go can target per OS — darwin/386 no longer exists.
const GEN_ARCHES = {
  windows: [['amd64', 'x64'], ['386', 'x86'], ['arm64', 'arm64']],
  linux: [['amd64', 'x64'], ['386', 'x86'], ['arm64', 'arm64']],
  darwin: [['amd64', 'x64'], ['arm64', 'arm64']],
};
// Arches each OS's shellcode backend actually implements.
const SHELLCODE_ARCHES = { windows: ['amd64', '386'], linux: ['amd64', 'arm64'], darwin: ['arm64'] };

// setSelectOptions replaces a select's options, keeping the current selection
// when it is still offered (so switching OS doesn't silently reset a choice
// that remains valid).
function setSelectOptions(sel, pairs) {
  const prev = sel.value;
  sel.innerHTML = '';
  for (const [value, label] of pairs) sel.appendChild(new Option(label, value));
  if (pairs.some(([v]) => v === prev)) sel.value = prev;
}

function updateGenTargetFields() {
  const os = $('#mgOs').value;
  setSelectOptions($('#mgArch'), GEN_ARCHES[os] || GEN_ARCHES.linux);
  let formats = GEN_FORMATS[os] || GEN_FORMATS.linux;
  const scArches = SHELLCODE_ARCHES[os];
  if (scArches && !scArches.includes($('#mgArch').value)) {
    formats = formats.filter(([v]) => v !== 'shellcode');
  }
  setSelectOptions($('#mgFormat'), formats);
  updateGenFormatFields();
  refreshEncoderOptions();
}
function updateGenFormatFields() {
  const os = $('#mgOs').value, format = $('#mgFormat').value;
  const isShellcode = format === 'shellcode';
  $('#mgShellcodeGroup').style.display = isShellcode ? '' : 'none';
  $('#mgRunAtLoadOpt').style.display = format === 'shared' ? '' : 'none';
  const winOnly = isShellcode && os === 'windows';
  $$('.mg-win', document).forEach((n) => n.style.display = winOnly ? '' : 'none');
  $('#mgShellcodeNote').textContent = winOnly
    ? 'Windows shellcode is generated with Donut; all options below apply.'
    : `${os} shellcode only supports compression — the Donut-specific options do not apply.`;
}
function updateGenTypeFields() {
  $('#mgBeaconSection').style.display = $('#mgType').value === 'beacon' ? '' : 'none';
}
$('#mgOs').addEventListener('change', updateGenTargetFields);
$('#mgArch').addEventListener('change', updateGenTargetFields);
$('#mgFormat').addEventListener('change', updateGenFormatFields);
$('#mgType').addEventListener('change', updateGenTypeFields);
updateGenTargetFields();
updateGenTypeFields();
async function refreshGenListenerList() {
  const sel = $('#mgListener');
  const prev = sel.value;
  sel.innerHTML = '';
  sel.appendChild(new Option('— Named Pipe (pivot) —', '__namedpipe__'));
  try {
    const jobs = await api('GET', '/api/jobs');
    let foundListeners = false;
    for (const j of (jobs || [])) {
      if (!['mtls', 'http', 'https'].includes(j.Name)) continue;
      foundListeners = true;
      const domain = (j.Domains && j.Domains[0]) ? ' · ' + j.Domains[0] : '';
      const opt = new Option(`${j.Name} · :${j.Port}${domain} (job ${j.ID})`, String(j.ID));
      opt.dataset.c2type = j.Name;
      opt.dataset.port = j.Port;
      sel.appendChild(opt);
    }
    // If no listeners, add a helper option
    if (!foundListeners) {
      const opt = new Option('(start a listener first)', '');
      opt.disabled = true;
      sel.appendChild(opt);
    }
  } catch (e) {
    const opt = new Option(`(error: ${e.message})`, '');
    opt.disabled = true;
    sel.appendChild(opt);
  }
  if (prev && Array.from(sel.options).some((o) => o.value === prev)) sel.value = prev;
  updateGenListenerFields();
  sel.dispatchEvent(new Event('change'));
}
$('#mgListener').addEventListener('change', async () => {
  updateGenListenerFields();
  const sel = $('#mgListener');
  const opt = sel.selectedOptions[0];

  if (sel.value === '__namedpipe__') {
    sel.dataset.c2type = 'named-pipe';
    return;
  }

  if (opt && opt.dataset.c2type) {
    sel.dataset.c2type = opt.dataset.c2type;
    if (opt.dataset.port) $('#mgPort').value = opt.dataset.port;
  }

  // Try to fetch and update host for mtls
  try {
    const jobs = await api('GET', '/api/jobs');
    const job = (jobs || []).find((j) => String(j.ID) === sel.value);
    if (job && job.Name === 'mtls') {
      const m = (job.Description || '').match(/mutual tls listener (.+):\d+$/);
      if (m) $('#mgHost').value = m[1];
    }
  } catch {}
});
$('#tbGenerate').onclick = () => openModal('generate');
$('#mgSave').onclick = async () => {
  const msg = $('#mgMsg');
  const format = $('#mgFormat').value;
  const type = $('#mgListener').dataset.c2type || 'named-pipe';
  const c2 = type === 'named-pipe'
    ? { C2Type: type, C2Host: $('#mgPipe').value.trim(), C2Port: 0 }
    : { C2Type: type, C2Host: $('#mgHost').value.trim(), C2Port: parseInt($('#mgPort').value, 10) || 0 };
  if (!c2.C2Host) { msg.className = 'err'; msg.textContent = type === 'named-pipe' ? 'enter a pipe path' : 'select (or start) a listener, then confirm the C2 host'; return; }
  if (type !== 'named-pipe' && !c2.C2Port) { msg.className = 'err'; msg.textContent = 'specify a C2 port'; return; }
  const savedir = $('#mgSavedir').value.trim();
  if (!savedir) { msg.className = 'err'; msg.textContent = 'specify a save directory'; return; }
  const isBeacon = $('#mgType').value === 'beacon';
  const opts = {
    OS: $('#mgOs').value, Arch: $('#mgArch').value, Format: format,
    IsBeacon: isBeacon,
    Interval: parseInt($('#mgInterval').value, 10) || 60, Jitter: parseInt($('#mgJitter').value, 10) || 0,
    Reconnect: parseInt($('#mgReconnect').value, 10) || 60, MaxErrors: parseInt($('#mgMaxErrors').value, 10) || 1000,
    Poll: parseInt($('#mgPoll').value, 10) || 360,
    Name: $('#mgName').value.trim(), SaveDir: savedir,
    Debug: $('#mgDebug').checked,
    Evasion: $('#mgEvasion').checked,
    ObfuscateSymbols: $('#mgObfuscate').checked,
    NetGo: $('#mgNetGo').checked,
    RunAtLoad: format === 'shared' && $('#mgRunAtLoad').checked,
    LimitDomainJoined: $('#mgLimitDomain').checked,
    PrependSize: $('#mgPrependSize').checked,
    LimitHostname: $('#mgLimitHost').value.trim(),
    LimitUsername: $('#mgLimitUser').value.trim(),
    LimitFileExists: $('#mgLimitFile').value.trim(),
    LimitLocale: $('#mgLimitLocale').value.trim(),
    LimitDatetime: $('#mgLimitDate').value.trim(),
    ...c2,
  };
  // Shellcode options (only for shellcode format)
  if (format === 'shellcode') {
    opts.ShellcodeEncoder = $('#mgEncoder').value;
    opts.ShellcodeCompress = $('#mgScCompress').checked;
    if ($('#mgOs').value === 'windows') {
      opts.ShellcodeEntropy = parseInt($('#mgScEntropy').value, 10) || 1;
      opts.ShellcodeExitOpt = parseInt($('#mgScExit').value, 10) || 1;
      opts.ShellcodeBypass = parseInt($('#mgScBypass').value, 10) || 3;
      opts.ShellcodeHeaders = parseInt($('#mgScHeaders').value, 10) || 1;
      opts.ShellcodeThread = $('#mgScThread').checked;
      opts.ShellcodeUnicode = $('#mgScUnicode').checked;
      opts.ShellcodeOEP = parseInt($('#mgScOEP').value, 10) || 0;
    }
  }
  msg.className = 'muted mono'; msg.textContent = 'building… (this can take a minute or two)';
  $('#mgSave').disabled = true;
  try {
    const r = await api('POST', '/api/generate', opts);
    msg.className = 'ok'; msg.textContent = `built ${r.name} (${fmtSize(r.size)}) — saved to ${r.savedPath}`;
    const p = ensurePane('implants'); if (p) loadImplants(p);
    setTimeout(closeModal, 2000);
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  finally { $('#mgSave').disabled = false; }
};

// ----- New Implant Profile -----
// A profile is a saved ImplantConfig — the blueprint `stage-listener` builds
// its stage 2 from. It exposes the same build knobs `profiles new` binds
// (client/command/generate/commands.go), including the shellcode tuning
// documented at https://sliver.sh/docs/?name=Stagers. Everything defaults to
// Sliver's own default, so an operator who only fills in name + C2 gets the
// same implant the old inline form produced.

// Shellcode encoder compatibility is per-architecture and only the server knows
// which encoders it has, so the list is fetched once and re-filtered on every
// arch change rather than hardcoded here.
let SHELLCODE_ENCODERS = null;
async function loadShellcodeEncoders() {
  if (SHELLCODE_ENCODERS) return SHELLCODE_ENCODERS;
  try { SHELLCODE_ENCODERS = await api('GET', '/api/shellcode-encoders'); }
  catch { SHELLCODE_ENCODERS = {}; }
  return SHELLCODE_ENCODERS;
}
async function refreshEncoderOptions() {
  const map = await loadShellcodeEncoders();
  const sel = $('#mpEncoder');
  const names = map[$('#mpArch').value] || [];
  setSelectOptions(sel, [['none', 'none'], ...names.map((n) => [n, n])]);
}

function updateProfileTargetFields() {
  const os = $('#mpOs').value;
  setSelectOptions($('#mpArch'), GEN_ARCHES[os] || GEN_ARCHES.linux);
  let formats = GEN_FORMATS[os] || GEN_FORMATS.linux;
  const scArches = SHELLCODE_ARCHES[os];
  if (scArches && !scArches.includes($('#mpArch').value)) formats = formats.filter(([v]) => v !== 'shellcode');
  setSelectOptions($('#mpFormat'), formats);
  updateProfileFormatFields();
  refreshEncoderOptions();
}
function updateProfileFormatFields() {
  const os = $('#mpOs').value, format = $('#mpFormat').value;
  const isShellcode = format === 'shellcode';
  $('#mpShellcodeGroup').style.display = isShellcode ? '' : 'none';
  // RunAtLoad drives the shared-library entrypoint (DllMain/constructor); it
  // means nothing for an exe or a service binary.
  $('#mpRunAtLoadOpt').style.display = format === 'shared' ? '' : 'none';
  // Everything but compression is Donut, and Donut is Windows-only — macOS
  // (beignet) and Linux (malasada) ignore the rest, so don't offer them.
  const winOnly = isShellcode && os === 'windows';
  $$('.mp-win', $('#modalProfile')).forEach((n) => n.style.display = winOnly ? '' : 'none');
  $('#mpShellcodeNote').textContent = winOnly
    ? 'Windows shellcode is generated with Donut; all options below apply.'
    : `${os} shellcode only supports compression — the Donut-specific options do not apply.`;
}
function updateProfileC2Fields() {
  const isPipe = $('#mpC2Type').value === 'named-pipe';
  $('#mpC2HostPortRow').style.display = isPipe ? 'none' : '';
  $('#mpPipeField').style.display = isPipe ? '' : 'none';
}
function updateProfileBeaconFields() {
  $('#mpBeaconSection').style.display = $('#mpType').value === 'beacon' ? '' : 'none';
}
$('#mpOs').addEventListener('change', updateProfileTargetFields);
$('#mpArch').addEventListener('change', updateProfileTargetFields);
$('#mpFormat').addEventListener('change', updateProfileFormatFields);
$('#mpC2Type').addEventListener('change', updateProfileC2Fields);
$('#mpType').addEventListener('change', updateProfileBeaconFields);

// openProfileModal opens the dialog to create a new profile, or — when passed a
// profile object from the table — to edit it. Editing pre-fills the form from
// the profile's Opts (the backend's reversed GenerateOptions) and locks the
// name: Sliver upserts a profile by name, so saving under a new name would make
// a second profile rather than rename this one.
async function openProfileModal(profile) {
  const editing = !!profile;
  $('#mpMsg').textContent = '';
  $('#mpWarn').style.display = 'none';
  $('#mpHead').textContent = editing ? `Edit Profile — ${profile.Name}` : 'New Implant Profile';
  $('#mpSave').textContent = editing ? 'Save changes' : 'Save profile';
  $('#mpName').readOnly = editing;
  $('#mpName').value = editing ? profile.Name : '';
  fillDatalist($('#mp-c2-host-list'), { v4only: true });
  if (editing) {
    await fillProfileForm(profile.Opts || {});
  } else {
    $('#mpPrependSize').checked = false;
    if (!$('#mpC2Host').value) $('#mpC2Host').value = preferredV4();
    updateProfileTargetFields();
    updateProfileC2Fields();
    updateProfileBeaconFields();
  }
  openModal('profile');
  (editing ? $('#mpC2Host') : $('#mpName')).focus();
}

// fillProfileForm pre-populates every modal field from a profile's Opts. Order
// matters: OS rebuilds the Arch/Format option lists and Arch rebuilds the
// encoder list, so each parent select is applied before its dependents, and the
// encoder options (fetched async) are awaited before the encoder value is set.
async function fillProfileForm(o) {
  $('#mpOs').value = o.OS || 'windows';
  updateProfileTargetFields();          // rebuild Arch + Format options for the OS
  if (o.Arch) $('#mpArch').value = o.Arch;
  updateProfileTargetFields();          // re-filter Format now that Arch is set
  if (o.Format) $('#mpFormat').value = o.Format;
  updateProfileFormatFields();
  await refreshEncoderOptions();        // populate encoder <option>s for the arch

  $('#mpC2Type').value = o.C2Type || 'http';
  updateProfileC2Fields();
  if (o.C2Type === 'named-pipe') { $('#mpPipe').value = o.C2Host || ''; }
  else { $('#mpC2Host').value = o.C2Host || ''; $('#mpC2Port').value = o.C2Port || ''; }

  $('#mpType').value = o.IsBeacon ? 'beacon' : 'session';
  updateProfileBeaconFields();
  $('#mpInterval').value = o.Interval || 60;
  $('#mpJitter').value = o.Jitter || 0;
  $('#mpReconnect').value = o.Reconnect || 60;
  $('#mpMaxErrors').value = o.MaxErrors || 1000;
  $('#mpPoll').value = o.Poll || 360;

  $('#mpDebug').checked = !!o.Debug;
  $('#mpEvasion').checked = !!o.Evasion;
  $('#mpObfuscate').checked = !!o.ObfuscateSymbols;
  $('#mpNetGo').checked = !!o.NetGo;
  $('#mpRunAtLoad').checked = !!o.RunAtLoad;
  $('#mpLimitDomain').checked = !!o.LimitDomainJoined;
  $('#mpPrependSize').checked = !!o.PrependSize;
  $('#mpLimitHost').value = o.LimitHostname || '';
  $('#mpLimitUser').value = o.LimitUsername || '';
  $('#mpLimitFile').value = o.LimitFileExists || '';
  $('#mpLimitLocale').value = o.LimitLocale || '';
  $('#mpLimitDate').value = o.LimitDatetime || '';

  $('#mpEncoder').value = o.ShellcodeEncoder || 'none';
  $('#mpScCompress').checked = !!o.ShellcodeCompress;
  $('#mpScThread').checked = !!o.ShellcodeThread;
  $('#mpScUnicode').checked = !!o.ShellcodeUnicode;
  $('#mpScEntropy').value = o.ShellcodeEntropy || 1;
  $('#mpScExit').value = o.ShellcodeExitOpt || 1;
  $('#mpScBypass').value = o.ShellcodeBypass || 3;
  $('#mpScHeaders').value = o.ShellcodeHeaders || 1;
  $('#mpScOEP').value = o.ShellcodeOEP || 0;
}

$('#mpSave').onclick = async () => {
  const msg = $('#mpMsg');
  const name = $('#mpName').value.trim();
  if (!name) { msg.className = 'err'; msg.textContent = 'enter a profile name'; return; }
  const type = $('#mpC2Type').value;
  const c2 = type === 'named-pipe'
    ? { C2Type: type, C2Host: $('#mpPipe').value.trim(), C2Port: 0 }
    : { C2Type: type, C2Host: $('#mpC2Host').value.trim(), C2Port: parseInt($('#mpC2Port').value, 10) || 0 };
  if (!c2.C2Host) { msg.className = 'err'; msg.textContent = type === 'named-pipe' ? 'enter a pipe path' : 'select a C2 host'; return; }
  if (type !== 'named-pipe' && !c2.C2Port) { msg.className = 'err'; msg.textContent = 'specify a C2 port'; return; }
  const format = $('#mpFormat').value;
  const opts = {
    Name: name,
    OS: $('#mpOs').value, Arch: $('#mpArch').value, Format: format,
    IsBeacon: $('#mpType').value === 'beacon',
    Interval: parseInt($('#mpInterval').value, 10) || 60,
    Jitter: parseInt($('#mpJitter').value, 10) || 0,
    Reconnect: parseInt($('#mpReconnect').value, 10) || 60,
    MaxErrors: parseInt($('#mpMaxErrors').value, 10) || 1000,
    Poll: parseInt($('#mpPoll').value, 10) || 360,

    Debug: $('#mpDebug').checked,
    Evasion: $('#mpEvasion').checked,
    ObfuscateSymbols: $('#mpObfuscate').checked,
    NetGo: $('#mpNetGo').checked,
    RunAtLoad: format === 'shared' && $('#mpRunAtLoad').checked,
    LimitDomainJoined: $('#mpLimitDomain').checked,
    // Not an ImplantConfig field — the bridge stores it against the profile
    // name and applies it when a stage listener serves this profile.
    PrependSize: $('#mpPrependSize').checked,
    LimitHostname: $('#mpLimitHost').value.trim(),
    LimitUsername: $('#mpLimitUser').value.trim(),
    LimitFileExists: $('#mpLimitFile').value.trim(),
    LimitLocale: $('#mpLimitLocale').value.trim(),
    LimitDatetime: $('#mpLimitDate').value.trim(),
    ...c2,
  };
  // The server rejects shellcode options on a non-shellcode build, so only send
  // them when they apply. Donut fields likewise go only to Windows.
  if (format === 'shellcode') {
    opts.ShellcodeEncoder = $('#mpEncoder').value;
    opts.ShellcodeCompress = $('#mpScCompress').checked;
    if ($('#mpOs').value === 'windows') {
      opts.ShellcodeEntropy = parseInt($('#mpScEntropy').value, 10) || 1;
      opts.ShellcodeExitOpt = parseInt($('#mpScExit').value, 10) || 1;
      opts.ShellcodeBypass = parseInt($('#mpScBypass').value, 10) || 3;
      opts.ShellcodeHeaders = parseInt($('#mpScHeaders').value, 10) || 1;
      opts.ShellcodeThread = $('#mpScThread').checked;
      opts.ShellcodeUnicode = $('#mpScUnicode').checked;
      opts.ShellcodeOEP = parseInt($('#mpScOEP').value, 10) || 0;
    }
  }
  msg.className = 'muted mono'; msg.textContent = 'saving…';
  $('#mpSave').disabled = true;
  try {
    await api('POST', '/api/profiles', opts);
    msg.className = 'ok'; msg.textContent = `saved profile "${name}"`;
    const p = ensurePane('profiles'); if (p) loadProfiles(p);
    setTimeout(closeModal, 900);
  } catch (e) { msg.className = 'err'; msg.textContent = e.message; }
  finally { $('#mpSave').disabled = false; }
};

// ----- Profile selector in Generate modal -----
async function refreshGenProfileList() {
  const sel = $('#mgProfile');
  sel.innerHTML = '<option value="">— no profile —</option>';
  try {
    const profiles = await api('GET', '/api/profiles');
    for (const p of (profiles || [])) {
      sel.appendChild(new Option(p.Name, p.Name));
    }
  } catch (e) {
    // non-fatal; profiles are optional
  }
}
$('#mgProfile').addEventListener('change', async () => {
  const name = $('#mgProfile').value.trim();
  if (!name) return;
  try {
    const profiles = await api('GET', '/api/profiles');
    const prof = (profiles || []).find((p) => p.Name === name);
    if (!prof) return;
    const cfg = prof.Config || {};
    // Pre-fill form from profile
    $('#mgOs').value = cfg.GOOS || 'windows';
    $('#mgArch').value = cfg.GOARCH || 'amd64';
    let fmt = 'exe';
    if (cfg.IsShellcode) fmt = 'shellcode';
    else if (cfg.Format === 3) fmt = 'shared';
    else if (cfg.Format === 4) fmt = 'service';
    $('#mgFormat').value = fmt;
    const isBeacon = cfg.BeaconInterval > 0;
    $('#mgType').value = isBeacon ? 'beacon' : 'session';
    updateGenTargetFields();
    if (isBeacon) {
      $('#mgInterval').value = Math.round(cfg.BeaconInterval / 1e9) || 60;
      $('#mgJitter').value = Math.round(cfg.BeaconJitter / 1e9) || 0;
      $('#mgReconnect').value = Math.round(cfg.ReconnectInterval / 1e9) || 60;
      $('#mgMaxErrors').value = cfg.MaxConnectionErrors || 1000;
      $('#mgPoll').value = Math.round(cfg.PollTimeout / 1e9) || 360;
    }
    // Build options
    $('#mgDebug').checked = cfg.Debug || false;
    $('#mgEvasion').checked = cfg.Evasion || false;
    $('#mgObfuscate').checked = cfg.ObfuscateSymbols || false;
    $('#mgNetGo').checked = cfg.NetGoEnabled || false;
    $('#mgRunAtLoad').checked = cfg.RunAtLoad || false;
    $('#mgLimitDomain').checked = cfg.LimitDomainJoined || false;
    // Staging
    $('#mgPrependSize').checked = (prof.PrependSize || false);
    // Execution limits
    $('#mgLimitHost').value = cfg.LimitHostname || '';
    $('#mgLimitUser').value = cfg.LimitUsername || '';
    $('#mgLimitFile').value = cfg.LimitFileExists || '';
    $('#mgLimitLocale').value = cfg.LimitLocale || '';
    $('#mgLimitDate').value = cfg.LimitDatetime || '';
    // Shellcode options
    if (fmt === 'shellcode') {
      $('#mgEncoder').value = cfg.ShellcodeEncoder || 'none';
      const sc = cfg.ShellcodeConfig || {};
      $('#mgScCompress').checked = sc.Compress === 2;
      $('#mgScEntropy').value = sc.Entropy || 1;
      $('#mgScExit').value = sc.ExitOpt || 1;
      $('#mgScBypass').value = sc.Bypass || 3;
      $('#mgScHeaders').value = sc.Headers || 1;
      $('#mgScThread').checked = cfg.ShellcodeThread || false;
      $('#mgScUnicode').checked = cfg.ShellcodeUnicode || false;
      $('#mgScOEP').value = cfg.ShellcodeOEP || 0;
    }
    // C2 setup
    const c2s = cfg.C2 || [];
    if (c2s.length > 0) {
      const c2url = new URL(c2s[0].URL);
      if (c2url.protocol.startsWith('namedpipe')) {
        const host = c2url.hostname;
        const path = c2url.pathname.replace(/\//g, '\\');
        $('#mgPipe').value = '\\\\' + host + path;
        $('#mgListener').value = '__namedpipe__';
      } else {
        $('#mgHost').value = c2url.hostname;
        $('#mgPort').value = c2url.port || 8888;
      }
    }
    updateGenListenerFields();
    updateGenTypeFields();
  } catch (e) {
    // Profile selection is best-effort
  }
});

// =====================================================================
// directory browser (bridge host filesystem — Generate's save dir)
// =====================================================================
const DIRB = { targetInput: null, current: null, parent: null };
function openDirBrowser(targetInput) {
  DIRB.targetInput = targetInput;
  $('#dirbrowser').style.display = 'flex';
  loadDirBrowser(targetInput.value.trim());
}
function closeDirBrowser() { $('#dirbrowser').style.display = 'none'; DIRB.targetInput = null; }
async function loadDirBrowser(path) {
  const list = $('#dirbrowser-list'); const msg = $('#dirbrowser-msg');
  list.innerHTML = '<div class="side-empty">loading…</div>'; msg.textContent = '';
  try {
    const r = await api('GET', '/api/browse-dirs' + (path ? '?path=' + encodeURIComponent(path) : ''));
    $('#dirbrowser-path').textContent = r.path;
    $('#dirbrowser-up').disabled = !r.parent;
    DIRB.current = r.path; DIRB.parent = r.parent;
    list.innerHTML = '';
    if (!r.dirs || !r.dirs.length) { list.innerHTML = '<div class="side-empty">no subdirectories</div>'; return; }
    for (const d of r.dirs) {
      const row = el('div', 'file-row');
      const nm = el('span', 'fn dir', '📁 ' + d.name);
      nm.onclick = () => loadDirBrowser(d.path);
      row.appendChild(nm);
      list.appendChild(row);
    }
  } catch (e) { msg.textContent = e.message; list.innerHTML = ''; }
}
$('#mgBrowse').onclick = () => openDirBrowser($('#mgSavedir'));
$('#mlRefresh').onclick = loadInterfaces;
$('#mgRefresh').onclick = loadInterfaces;
$('#dirbrowser-close').onclick = closeDirBrowser;
$('#dirbrowser-up').onclick = () => { if (DIRB.parent) loadDirBrowser(DIRB.parent); };
$('#dirbrowser-select').onclick = () => { if (DIRB.targetInput && DIRB.current) DIRB.targetInput.value = DIRB.current; closeDirBrowser(); };
$('#dirbrowser').addEventListener('click', (e) => { if (e.target.id === 'dirbrowser') closeDirBrowser(); });

// =====================================================================
// boot
// =====================================================================
api('GET', '/api/config').then((c) => {
  $('#conn').innerHTML = `${esc(c.operator)} @ ${esc(c.server)}`;
}).catch((e) => { $('#conn').textContent = 'error: ' + e.message; });

initEventLog();
loadInterfaces();
loadAgents();
setInterval(loadAgents, 5000);
startEvents();

// Save/restore active tab
function restoreActiveTab() {
  const savedTab = localStorage.getItem('lastTab');
  if (!savedTab) return;
  // Utility tabs (profiles, implants, jobs, etc)
  if (['log', 'jobs', 'stagelisteners', 'profiles', 'implants', 'pivotgraph', 'help', 'console'].includes(savedTab)) {
    openUtilTab(savedTab);
  } else if (STATE.agents[savedTab]) {
    // Agent tab — restore if the agent is still connected
    const rec = STATE.agents[savedTab];
    showAgentPane(savedTab, rec.a);
  }
}
function saveActiveTab() {
  const activeTab = dockTabs.querySelector('.dtab.active');
  if (activeTab && activeTab.dataset.tab) {
    localStorage.setItem('lastTab', activeTab.dataset.tab);
  }
}
dockTabs.addEventListener('click', (e) => {
  const tab = e.target.closest('.dtab');
  if (tab) setTimeout(saveActiveTab, 0);
});

// Restore tab after agents load (they may be recreated)
const originalLoadAgents = loadAgents;
window.loadAgents = async function() {
  const result = await originalLoadAgents.call(this);
  setTimeout(restoreActiveTab, 100);
  return result;
};

// Restore on boot
setTimeout(restoreActiveTab, 800);
