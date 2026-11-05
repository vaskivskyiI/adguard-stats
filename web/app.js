'use strict';
/* AdGuard Stats dashboard. Plain JS + ECharts; all data comes from /api. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const dark = matchMedia('(prefers-color-scheme: dark)').matches;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const DEFAULTS = {
  tab: 'overview', preset: '7', start: '', end: '', persons: [], clients: [], categories: [], q: '', hideBg: true,
  metric: 'minutes', ovSplit: 'category', cmpMode: 'people', cmpBy: 'category', cmpShare: false,
  cmpB: 'prev', cmpBStart: '', cmpBEnd: '', exKind: 'categories', exTarget: '', tlSplit: 'person', tlDay: '',
  stSort: 'queries', stPage: 0,
};
const state = Object.assign({}, DEFAULTS, loadState());
let META = null;

function loadState() { try { return JSON.parse(localStorage.getItem('ags-state') || '{}'); } catch { return {}; } }
function saveState() { try { localStorage.setItem('ags-state', JSON.stringify(state)); } catch { /* storage unavailable */ } }

// ---------------------------------------------------------------- formatting
const nf = new Intl.NumberFormat();
const cf = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });
function fmtMin(m) {
  m = Math.round(m || 0);
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  return h >= 100 ? nf.format(h) + 'h' : `${h}h ${String(m % 60).padStart(2, '0')}m`;
}
const fmtVal = (metric, v) => metric === 'minutes' ? fmtMin(v) : nf.format(Math.round(v || 0));
const fmtAxis = (metric, v) => metric === 'minutes' ? (v >= 60 ? +(v / 60).toFixed(1) + 'h' : v + 'm') : cf.format(v);
const pct = (v, d = 1) => v == null ? '–' : (v * 100).toFixed(d) + '%';
const metricName = m => ({ minutes: 'Active time', queries: 'Queries', blocked: 'Blocked queries' }[m]);
const fmtDate = ms => ms ? new Date(ms).toLocaleString() : '–';
const iso = d => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
const parseISO = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const addDays = (s, n) => { const d = parseISO(s); d.setDate(d.getDate() + n); return iso(d); };
const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / 864e5) + 1;

// ---------------------------------------------------------------- colors
const PALETTE = ['#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f', '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#86bcb6', '#d37295', '#8cd17d', '#499894', '#f1ce63', '#a0cbe8', '#79706e'];
const CAT_COLORS = {
  'Social networks': '#e15759', 'Messaging': '#f28e2b', 'Video & streaming': '#4e79a7', 'Music & audio': '#76b7b2',
  'Gaming': '#59a14f', 'Shopping': '#edc948', 'News & media': '#b07aa1', 'Search & portals': '#9c755f',
  'Email & productivity': '#86bcb6', 'Education & reference': '#8cd17d', 'AI tools': '#d37295', 'Finance': '#499894',
  'Travel & maps': '#a0cbe8', 'Dating': '#ff9da7', 'Gambling': '#d4a6c8', 'Privacy & VPN': '#f1ce63',
  'Software & updates': '#bab0ac', 'Smart home & IoT': '#8fb8de', 'Ads & tracking': '#6b6b6b', 'Infrastructure': '#999999',
  'Local network': '#b5b5b5', 'Other': '#cfcfcf',
};
function hashColor(s) { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) | 0; return PALETTE[Math.abs(h) % PALETTE.length]; }
function colorFor(split, key, name) {
  if (key === '__other__') return '#b0b0b0';
  if (split === 'category') return CAT_COLORS[key] || hashColor(key);
  if (split === 'person') { const p = META?.persons.find(p => p.id === key); return p?.color || (key === 0 ? '#9aa0a6' : hashColor(name)); }
  return hashColor(name ?? key);
}

// ---------------------------------------------------------------- api
function params(extra = {}) {
  const p = new URLSearchParams();
  const f = { start: state.start, end: state.end, persons: state.persons, clients: state.clients, categories: state.categories,
    q: state.q, hide_bg: state.hideBg, ...extra };
  for (const [k, v] of Object.entries(f)) {
    if (v == null || v === '') continue;
    if (Array.isArray(v)) v.forEach(x => p.append(k, x)); else p.set(k, v);
  }
  return p.toString();
}
async function api(path, extra, opts) {
  const url = opts ? path : `${path}?${params(extra)}`;
  // resolve against origin + path: a page URL with user:password@ makes relative fetches fail
  const r = await fetch(new URL(url, location.origin + location.pathname), opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { const j = await r.json(); msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch { /* not json */ }
    toast(`Error: ${msg}`);
    throw new Error(msg);
  }
  return r.json();
}
const send = (method, path, body) => api(path, null, { method, headers: { 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
let toastTimer;
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 3000); }

// ---------------------------------------------------------------- charts
const charts = {};
function chart(id, option) {
  const el = document.getElementById(id);
  let c = charts[id];
  if (!c) { c = echarts.init(el, dark ? 'dark' : null); charts[id] = c; }
  c.setOption(Object.assign({ backgroundColor: 'transparent', animationDuration: 300 }, option), true);
  return c;
}
function empty(id, text = 'No data for this selection') {
  chart(id, { title: { text, left: 'center', top: 'middle', textStyle: { fontSize: 13, fontWeight: 'normal', color: '#888' } } });
}
addEventListener('resize', () => Object.values(charts).forEach(c => c.resize()));

function tsOption(ts, metric, split) {
  const hourly = ts.bucket === 'hour';
  const bars = ts.labels.length <= 62;
  const series = ts.series.map(s => ({
    name: s.name, type: bars ? 'bar' : 'line', stack: 'all', areaStyle: bars ? undefined : { opacity: .7 },
    symbol: 'none', barMaxWidth: 40, itemStyle: { color: colorFor(split, s.key, s.name) }, lineStyle: { width: 1 },
    emphasis: { focus: 'series' },
    data: hourly ? s.data.map((v, i) => [ts.labels[i], v]) : s.data,
  }));
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: v => fmtVal(metric, v), confine: true },
    legend: { type: 'scroll', top: 0, show: ts.series.length > 1 },
    grid: { left: 50, right: 16, top: ts.series.length > 1 ? 32 : 12, bottom: 30 },
    xAxis: hourly ? { type: 'time' } : { type: 'category', data: ts.labels },
    yAxis: { type: 'value', axisLabel: { formatter: v => fmtAxis(metric, v) } },
    series,
  };
}
function heatOption(h, metric) {
  const data = [];
  let max = 0;
  h.values.forEach((row, w) => row.forEach((v, hr) => { data.push([hr, w, v]); max = Math.max(max, v); }));
  return {
    tooltip: { formatter: p => `${['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][p.value[1]]} ${p.value[0]}:00 – ${fmtVal(metric, p.value[2])}` },
    grid: { left: 40, right: 10, top: 10, bottom: 70 },
    xAxis: { type: 'category', data: [...Array(24).keys()].map(String), splitArea: { show: true } },
    yAxis: { type: 'category', data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], inverse: true },
    visualMap: { min: 0, max: max || 1, calculable: true, orient: 'horizontal', left: 'center', bottom: 0, itemHeight: 120,
      inRange: { color: dark ? ['#1b1f27', '#2e4a7d', '#6d9bff', '#ffd166'] : ['#f4f6fa', '#9cb9ef', '#3b6fd8', '#c2185b'] },
      formatter: v => fmtAxis(metric, Math.round(v)) },
    series: [{ type: 'heatmap', data, emphasis: { itemStyle: { borderColor: '#000', borderWidth: 1 } } }],
  };
}
function hbarOption(rows, metric, colorKey) {
  rows = rows.slice().reverse();
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: v => fmtVal(metric, v) },
    grid: { left: 130, right: 30, top: 8, bottom: 24 },
    xAxis: { type: 'value', axisLabel: { formatter: v => fmtAxis(metric, v) } },
    yAxis: { type: 'category', data: rows.map(r => r.name), axisLabel: { width: 120, overflow: 'truncate' } },
    series: [{ type: 'bar', data: rows.map(r => ({ value: r[metric], itemStyle: { color: colorKey ? colorFor('category', r[colorKey]) : PALETTE[0] } })) }],
  };
}

// ---------------------------------------------------------------- tables
function table(el, cols, rows, onClick) {
  const head = cols.map(c => `<th class="${c.n ? 'n' : ''}${c.sort ? ' sort' : ''}" data-sort="${c.sort || ''}">${esc(c.t)}${c.sort && c.sort === state.stSort ? ' ▾' : ''}</th>`).join('');
  const body = rows.length ? rows.map((r, i) => `<tr data-i="${i}" class="${onClick ? 'click' : ''}">${cols.map(c => `<td class="${c.n ? 'n' : ''}">${c.f ? c.f(r) : esc(r[c.k])}</td>`).join('')}</tr>`).join('')
    : `<tr><td colspan="${cols.length}" class="hint">No data</td></tr>`;
  el.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
  if (onClick) $$('tbody tr[data-i]', el).forEach(tr => tr.addEventListener('click', ev => {
    if (ev.target.closest('select,input,button')) return;
    onClick(rows[+tr.dataset.i]);
  }));
  return el;
}
const catTag = c => c ? `<span class="tag"><span class="dot" style="background:${colorFor('category', c)}"></span>${esc(c)}</span>` : '';

// ---------------------------------------------------------------- filters UI
function multiSelect(el, title, items, selected, onChange) {
  const sel = new Set(selected);
  const label = () => {
    const names = items.filter(i => sel.has(i.v)).map(i => i.l);
    return `${title}: ${names.length === 0 ? 'All' : names.length <= 2 ? names.join(', ') : names.length + ' selected'}`;
  };
  el.innerHTML = `<button type="button" aria-haspopup="true">${esc(label())}</button>`;
  const btn = el.firstChild;
  btn.onclick = ev => {
    ev.stopPropagation();
    const open = $('.pop', el);
    $$('.ms .pop').forEach(p => p.remove());
    if (open) return;
    const pop = document.createElement('div');
    pop.className = 'pop';
    pop.innerHTML = `<div class="acts"><button type="button" data-a="none">All</button>${items.length > 8 ? '<input type="search" placeholder="Filter…" style="flex:1;min-width:0">' : ''}</div>` +
      items.map((it, i) => `<label data-l="${esc(it.l.toLowerCase())}"><input type="checkbox" data-i="${i}" ${sel.has(it.v) ? 'checked' : ''}>${it.dot ? `<span class="dot" style="background:${it.dot}"></span>` : ''}${esc(it.l)}</label>`).join('');
    pop.onclick = e => e.stopPropagation();
    pop.addEventListener('change', e => {
      if (!e.target.dataset.i) return;
      const it = items[+e.target.dataset.i];
      e.target.checked ? sel.add(it.v) : sel.delete(it.v);
      btn.textContent = label();
      onChange([...sel]);
    });
    $('[data-a=none]', pop).onclick = () => { sel.clear(); $$('input[type=checkbox]', pop).forEach(c => c.checked = false); btn.textContent = label(); onChange([]); };
    const search = $('input[type=search]', pop);
    if (search) search.oninput = () => $$('label', pop).forEach(l => l.style.display = l.dataset.l.includes(search.value.toLowerCase()) ? '' : 'none');
    el.appendChild(pop);
    search?.focus();
  };
}
document.addEventListener('click', () => $$('.ms .pop').forEach(p => p.remove()));

function applyPreset() {
  const today = META?.today || iso(new Date());
  const p = state.preset;
  if (p === 'custom') return;
  if (p === 'today') { state.start = state.end = today; }
  else if (p === 'yesterday') { state.start = state.end = addDays(today, -1); }
  else if (p === 'month') { state.start = today.slice(0, 8) + '01'; state.end = today; }
  else if (p === 'lastmonth') { const first = today.slice(0, 8) + '01'; state.end = addDays(first, -1); state.start = state.end.slice(0, 8) + '01'; }
  else if (p === 'all') { state.start = META?.first_day || today; state.end = today; }
  else { state.end = today; state.start = addDays(today, -(+p - 1)); }
}

let refreshTimer;
function changed() { saveState(); clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 150); }

function buildFilters() {
  $('#f-preset').value = state.preset;
  $('#f-start').value = state.start; $('#f-end').value = state.end;
  $('#f-q').value = state.q; $('#f-hidebg').checked = state.hideBg;
  const personItems = META.persons.map(p => ({ v: p.id, l: p.name, dot: p.color || hashColor(p.name) })).concat([{ v: 0, l: 'Unassigned' }]);
  multiSelect($('#f-persons'), 'Persons', personItems, state.persons, v => { state.persons = v; changed(); });
  const clientItems = META.clients.map(c => ({ v: c.id, l: `${c.label || c.name || c.ip}${(c.label || c.name) ? ' (' + c.ip + ')' : ''}` }));
  multiSelect($('#f-clients'), 'Devices', clientItems, state.clients, v => { state.clients = v; changed(); });
  const catItems = META.categories.map(c => ({ v: c, l: c, dot: colorFor('category', c) }));
  multiSelect($('#f-categories'), 'Categories', catItems, state.categories, v => { state.categories = v; changed(); });
  $$('#f-metric button').forEach(b => b.classList.toggle('on', b.dataset.v === state.metric));
}
$('#f-preset').onchange = e => { state.preset = e.target.value; applyPreset(); $('#f-start').value = state.start; $('#f-end').value = state.end; changed(); };
$('#f-start').onchange = e => { state.start = e.target.value; state.preset = 'custom'; $('#f-preset').value = 'custom'; changed(); };
$('#f-end').onchange = e => { state.end = e.target.value; state.preset = 'custom'; $('#f-preset').value = 'custom'; changed(); };
$('#f-q').oninput = e => { state.q = e.target.value.trim(); clearTimeout(refreshTimer); refreshTimer = setTimeout(() => { saveState(); refresh(); }, 400); };
$('#f-hidebg').onchange = e => { state.hideBg = e.target.checked; changed(); };
$$('#f-metric button').forEach(b => b.onclick = () => { state.metric = b.dataset.v; $$('#f-metric button').forEach(x => x.classList.toggle('on', x === b)); changed(); });

function showTab(tab) {
  state.tab = tab;
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === tab));
  $$('.tab').forEach(t => t.classList.toggle('on', t.id === 'tab-' + tab));
  if (location.hash !== '#' + tab) history.replaceState(null, '', '#' + tab);
  saveState();
  refresh();
}
$$('#tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));

async function loadMeta() {
  META = await api('api/meta', null, {});
  const st = META.collector || {};
  const el = $('#status');
  el.className = 'status' + (st.last_error ? ' err' : (st.backfilling || st.regroup_pending) ? ' busy' : '');
  el.textContent = st.last_error ? 'Collector error' : st.backfilling ? `Importing history… (at ${st.backfill_at ? new Date(st.backfill_at).toLocaleString() : 'start'})` : st.regroup_pending ? `Re-categorizing (${st.regroup_pending} days)` :
    st.last_success ? 'Updated ' + new Date(st.last_success * 1000).toLocaleTimeString() : 'Starting…';
  el.title = st.last_error || `Source: ${META.adguard_url}`;
  if (!META.auth) {
    el.className = 'status err';
    el.textContent = 'No password set: ' + el.textContent;
    el.title = 'DASHBOARD_PASSWORD is empty, so anyone who can reach this page sees the stats. Set it in .env.';
  }
  $('#cat-options').innerHTML = META.categories.map(c => `<option value="${esc(c)}">`).join('');
}

const renderers = {};
let renderSeq = 0;
async function refresh() {
  const seq = ++renderSeq;
  try { await renderers[state.tab](seq); } catch (e) { console.error(e); }
  requestAnimationFrame(() => Object.values(charts).forEach(c => c.resize()));
}
const stale = seq => seq !== renderSeq;

// ---------------------------------------------------------------- overview
function kpiCards(el, cur, prev, days) {
  const delta = (k, invert) => {
    if (!prev || prev[k] == null || cur[k] == null || !prev[k]) return '';
    const d = (cur[k] - prev[k]) / prev[k];
    const cls = Math.abs(d) < .005 ? '' : ((d > 0) !== !!invert ? 'up' : 'down');
    return `<span class="${cls}">${d > 0 ? '▲' : '▼'} ${Math.abs(d * 100).toFixed(0)}%</span> vs previous ${days}d`;
  };
  const k = [
    ['Active time (est.)', fmtMin(cur.minutes), delta('minutes')],
    ['Per day', fmtMin(cur.minutes_per_day), delta('minutes_per_day')],
    ['Queries', nf.format(cur.queries), delta('queries')],
    ['Blocked', `${nf.format(cur.blocked)} <small>(${pct(cur.block_rate)})</small>`, delta('blocked', true)],
    ['Sites', nf.format(cur.sites), delta('sites')],
    ['New sites', nf.format(cur.new_sites), ''],
    ['Devices', nf.format(cur.devices), ''],
    ['Avg latency', cur.latency_ms == null ? '–' : cur.latency_ms + ' ms', delta('latency_ms')],
    ['Cache hits', pct(cur.cache_rate), ''],
  ];
  el.innerHTML = k.map(([l, v, d]) => `<div class="kpi"><div class="l">${l}</div><div class="v">${v}</div><div class="d">${d || '&nbsp;'}</div></div>`).join('');
}

renderers.overview = async seq => {
  $('#ov-split').value = state.ovSplit;
  const m = state.metric;
  const [sum, ts, cats, heat, svc, sites] = await Promise.all([
    api('api/summary'), api('api/timeseries', { metric: m, split: state.ovSplit }),
    api('api/top', { by: 'category', sort: m, limit: 30 }), api('api/heatmap', { metric: m }),
    api('api/top', { by: 'service', sort: m, limit: 15 }), api('api/top', { by: 'site', sort: m, limit: 30 }),
  ]);
  if (stale(seq)) return;
  kpiCards($('#kpis'), sum.current, sum.previous, sum.days);
  $('#ts-title').textContent = `${metricName(m)} over time (per ${ts.bucket})`;
  ts.series.length ? chart('ov-ts', tsOption(ts, m, state.ovSplit)) : empty('ov-ts');
  const catRows = cats.rows.filter(r => r[m] > 0);
  catRows.length ? chart('ov-cats', {
    tooltip: { trigger: 'item', valueFormatter: v => fmtVal(m, v) },
    legend: { type: 'scroll', orient: 'vertical', right: 0, top: 'middle' },
    series: [{ type: 'pie', radius: ['45%', '75%'], center: ['35%', '50%'], label: { show: false },
      data: catRows.map(r => ({ name: r.name, value: r[m], itemStyle: { color: colorFor('category', r.key) } })) }],
  }) : empty('ov-cats');
  $('#ov-heat-note').textContent = heat.clipped_to ? `hour detail since ${heat.clipped_to}` : '';
  chart('ov-heat', heatOption(heat, m));
  svc.rows.length ? chart('ov-svc', hbarOption(svc.rows.filter(r => r[m] > 0), m, 'category')) : empty('ov-svc');
  table($('#ov-sites'), [
    { t: 'Site', k: 'name' }, { t: 'Category', f: r => catTag(r.category) },
    { t: 'Time', n: 1, f: r => fmtMin(r.minutes) }, { t: 'Queries', n: 1, f: r => nf.format(r.queries) },
    { t: 'Blocked', n: 1, f: r => nf.format(r.blocked) },
  ], sites.rows, r => explore('sites', r.key));
};
$('#ov-split').onchange = e => { state.ovSplit = e.target.value; changed(); };

// ---------------------------------------------------------------- people
renderers.people = async seq => {
  const [bd, ins, ts] = await Promise.all([
    api('api/breakdown', { rows: 'person', cols: 'category', metric: 'minutes', limit: 14 }),
    api('api/insights'), api('api/timeseries', { metric: 'minutes', split: 'person', top: 100, bucket: 'day' }),
  ]);
  if (stale(seq)) return;
  if (bd.rows.length) {
    chart('pp-stack', {
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: v => fmtMin(v), confine: true },
      legend: { type: 'scroll', top: 0 }, grid: { left: 110, right: 20, top: 34, bottom: 24 },
      xAxis: { type: 'value', axisLabel: { formatter: v => fmtAxis('minutes', v) } },
      yAxis: { type: 'category', data: bd.rows.map(r => r.name), inverse: true },
      series: bd.cols.map((c, j) => ({ name: c.name, type: 'bar', stack: 'all', itemStyle: { color: colorFor('category', c.key) },
        emphasis: { focus: 'series' }, data: bd.values.map(row => row[j]) })),
    });
  } else empty('pp-stack');

  const cards = $('#pp-cards');
  cards.innerHTML = ins.persons.map((p, i) => {
    const color = colorFor('person', p.person, p.name);
    const maxCat = Math.max(1, ...p.top_categories.map(c => c.minutes));
    const maxSvc = Math.max(1, ...p.top_services.map(c => c.minutes));
    return `<div class="card person">
      <h3><span class="dot" style="background:${color}"></span>${esc(p.name)}</h3>
      <div class="stats">
        <div><span>Total</span> ${fmtMin(p.minutes)}</div><div><span>Per day</span> ${fmtMin(p.avg_per_day)}</div>
        <div><span>Weekdays</span> ${p.weekday_avg == null ? '–' : fmtMin(p.weekday_avg)}</div><div><span>Weekends</span> ${p.weekend_avg == null ? '–' : fmtMin(p.weekend_avg)}</div>
        <div><span>Night (0–5h)</span> ${fmtMin(p.night_minutes)}</div><div><span>Peak hour</span> ${p.peak_hour == null ? '–' : p.peak_hour + ':00'}</div>
        <div><span>Queries</span> ${cf.format(p.queries)}</div><div><span>Blocked</span> ${pct(p.block_rate)}</div>
      </div>
      <div class="mini" id="pp-mini-${i}"></div>
      <div class="hint">Top categories</div>
      <ul>${p.top_categories.map(c => `<li><span>${catTag(c.name)}</span><span class="n">${fmtMin(c.minutes)}</span><div class="bar" style="width:${c.minutes / maxCat * 100}%;background:${colorFor('category', c.name)}"></div></li>`).join('')}</ul>
      <div class="hint">Top services</div>
      <ul>${p.top_services.map(c => `<li><span>${esc(c.name)}</span><span class="n">${fmtMin(c.minutes)}</span><div class="bar" style="width:${c.minutes / maxSvc * 100}%"></div></li>`).join('')}</ul>
      ${p.spikes.length ? `<div class="warn">Unusual days: ${p.spikes.slice(0, 5).map(s => `${s.day} (${fmtMin(s.minutes)})`).join(', ')}</div>` : ''}
      <div class="acts"><button data-act="focus" data-p="${p.person}">Focus</button><button data-act="timeline" data-p="${p.person}">Day timeline</button></div>
    </div>`;
  }).join('') || '<div class="card hint">No activity. Assign devices to persons in Settings.</div>';
  ins.persons.forEach((p, i) => {
    const s = ts.series.find(x => x.key === p.person);
    const id = `pp-mini-${i}`;
    delete charts[id];
    chart(id, {
      grid: { left: 0, right: 0, top: 4, bottom: 0 }, tooltip: { trigger: 'axis', valueFormatter: v => fmtMin(v) },
      xAxis: { type: 'category', data: ts.labels, show: false }, yAxis: { type: 'value', show: false },
      series: [{ type: 'bar', data: s ? s.data : [], itemStyle: { color: colorFor('person', p.person, p.name) } }],
    });
  });
  $$('button[data-act]', cards).forEach(b => b.onclick = () => {
    state.persons = [+b.dataset.p];
    buildFilters();
    showTab(b.dataset.act === 'timeline' ? 'timeline' : 'overview');
  });
};

// ---------------------------------------------------------------- compare
function periodB() {
  const n = daysBetween(state.start, state.end);
  if (state.cmpB === 'year') return { start: addDays(state.start, -364), end: addDays(state.end, -364) };
  if (state.cmpB === 'custom' && state.cmpBStart && state.cmpBEnd) return { start: state.cmpBStart, end: state.cmpBEnd };
  return { start: addDays(state.start, -n), end: addDays(state.start, -1) };
}
renderers.compare = async seq => {
  const m = state.metric, by = state.cmpBy, share = state.cmpShare;
  $$('#cmp-mode button').forEach(b => b.classList.toggle('on', b.dataset.v === state.cmpMode));
  $('#cmp-by').value = by; $('#cmp-share').checked = share;
  $('#cmp-periods').classList.toggle('hidden', state.cmpMode !== 'periods');
  const shareOf = (vals, total) => vals.map(v => total ? +(v / total * 100).toFixed(1) : 0);
  const fmtV = v => share ? v + '%' : fmtVal(m, v);
  const barOpt = (cols, series) => ({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: fmtV, confine: true },
    legend: { top: 0, type: 'scroll' }, grid: { left: 50, right: 16, top: 34, bottom: 70 },
    xAxis: { type: 'category', data: cols, axisLabel: { rotate: 30, width: 110, overflow: 'truncate' } },
    yAxis: { type: 'value', axisLabel: { formatter: v => share ? v + '%' : fmtAxis(m, v) } }, series,
  });

  if (state.cmpMode === 'people') {
    $('#cmp-hint').textContent = state.persons.length >= 2 ? '' : 'Tip: pick persons in the filter bar to compare a subset.';
    const [bd, ts] = await Promise.all([
      api('api/breakdown', { rows: 'person', cols: by, metric: m, limit: 14 }),
      api('api/timeseries', { metric: m, split: 'person', top: 20 }),
    ]);
    if (stale(seq)) return;
    if (!bd.rows.length) { empty('cmp-bars'); empty('cmp-trend'); $('#cmp-table').innerHTML = ''; return; }
    const vals = bd.rows.map((r, i) => share ? shareOf(bd.values[i], r.total) : bd.values[i]);
    chart('cmp-bars', barOpt(bd.cols.map(c => c.name), bd.rows.map((r, i) => ({
      name: r.name, type: 'bar', itemStyle: { color: colorFor('person', r.key, r.name) }, data: vals[i] }))));
    $('#cmp-trend-title').textContent = `${metricName(m)} per person`;
    const lineTs = Object.assign({}, ts, { series: ts.series });
    const opt = tsOption(lineTs, m, 'person');
    opt.series.forEach(s => { s.type = 'line'; delete s.stack; delete s.areaStyle; s.symbol = 'none'; s.lineStyle = { width: 2 }; });
    chart('cmp-trend', opt);
    table($('#cmp-table'), [{ t: by[0].toUpperCase() + by.slice(1), k: 'name' },
      ...bd.rows.map((r, i) => ({ t: r.name, n: 1, f: row => fmtV(vals[i][row.j]) }))],
      bd.cols.map((c, j) => ({ name: c.name, j })));
  } else {
    $('#cmp-hint').textContent = '';
    const b = periodB();
    $('#cmp-b-preset').value = state.cmpB; $('#cmp-b-start').value = b.start; $('#cmp-b-end').value = b.end;
    const [ba, bb, ta, tb] = await Promise.all([
      api('api/breakdown', { rows: 'none', cols: by, metric: m, limit: 30 }),
      api('api/breakdown', { rows: 'none', cols: by, metric: m, limit: 30, start: b.start, end: b.end }),
      api('api/timeseries', { metric: m, bucket: 'day' }),
      api('api/timeseries', { metric: m, bucket: 'day', start: b.start, end: b.end }),
    ]);
    if (stale(seq)) return;
    const mapB = {};
    bb.cols.forEach((c, j) => mapB[c.key] = bb.values[0]?.[j] || 0);
    const keys = [...new Set([...ba.cols.map(c => c.key), ...bb.cols.map(c => c.key)])].slice(0, 14);
    const mapA = {};
    ba.cols.forEach((c, j) => mapA[c.key] = ba.values[0]?.[j] || 0);
    const totA = ba.rows[0]?.total || 0, totB = bb.rows[0]?.total || 0;
    let A = keys.map(k => mapA[k] || 0), B = keys.map(k => mapB[k] || 0);
    if (share) { A = shareOf(A, totA); B = shareOf(B, totB); }
    const la = `A: ${state.start} – ${state.end}`, lb = `B: ${b.start} – ${b.end}`;
    chart('cmp-bars', barOpt(keys, [
      { name: la, type: 'bar', data: A, itemStyle: { color: PALETTE[0] } }, { name: lb, type: 'bar', data: B, itemStyle: { color: PALETTE[1] } }]));
    $('#cmp-trend-title').textContent = 'Day by day (aligned)';
    const sA = ta.series[0]?.data || [], sB = tb.series[0]?.data || [];
    const n = Math.max(sA.length, sB.length);
    chart('cmp-trend', {
      tooltip: { trigger: 'axis', valueFormatter: v => fmtVal(m, v) }, legend: { top: 0 },
      grid: { left: 50, right: 16, top: 30, bottom: 30 },
      xAxis: { type: 'category', data: [...Array(n).keys()].map(i => 'Day ' + (i + 1)) },
      yAxis: { type: 'value', axisLabel: { formatter: v => fmtAxis(m, v) } },
      series: [{ name: la, type: 'line', data: sA, symbol: 'none', itemStyle: { color: PALETTE[0] } },
        { name: lb, type: 'line', data: sB, symbol: 'none', itemStyle: { color: PALETTE[1] } }],
    });
    table($('#cmp-table'), [{ t: 'Group', k: 'k' }, { t: 'A', n: 1, f: r => fmtV(r.a) }, { t: 'B', n: 1, f: r => fmtV(r.b) },
      { t: 'Change', n: 1, f: r => { const d = r.b ? (r.a - r.b) / r.b : null; return d == null ? 'new' : `<span class="${d > 0 ? 'up' : 'down'}">${d > 0 ? '+' : ''}${(d * 100).toFixed(0)}%</span>`; } }],
      keys.map((k, i) => ({ k, a: A[i], b: B[i] })));
  }
};
$$('#cmp-mode button').forEach(b => b.onclick = () => { state.cmpMode = b.dataset.v; changed(); });
$('#cmp-by').onchange = e => { state.cmpBy = e.target.value; changed(); };
$('#cmp-share').onchange = e => { state.cmpShare = e.target.checked; changed(); };
$('#cmp-b-preset').onchange = e => { state.cmpB = e.target.value; changed(); };
$('#cmp-b-start').onchange = e => { state.cmpB = 'custom'; state.cmpBStart = e.target.value; state.cmpBEnd ||= $('#cmp-b-end').value; changed(); };
$('#cmp-b-end').onchange = e => { state.cmpB = 'custom'; state.cmpBEnd = e.target.value; state.cmpBStart ||= $('#cmp-b-start').value; changed(); };

// ---------------------------------------------------------------- explore
function explore(kind, target) { state.exKind = kind; state.exTarget = target; showTab('explore'); }
function exploreFilter() {
  const t = state.exTarget;
  return { categories: state.exKind === 'categories' ? [t] : [], services: state.exKind === 'services' ? [t] : [],
    sites: state.exKind === 'sites' ? [t] : [], q: '' };
}
let siteLookupTimer;
function fillExploreOptions() {
  const list = $('#ex-options');
  if (state.exKind === 'categories') list.innerHTML = META.categories.map(c => `<option value="${esc(c)}">`).join('');
  else if (state.exKind === 'services') list.innerHTML = META.services.map(c => `<option value="${esc(c)}">`).join('');
  else list.innerHTML = '';
}
$('#ex-kind').onchange = e => { state.exKind = e.target.value; fillExploreOptions(); };
$('#ex-target').oninput = e => {
  if (state.exKind !== 'sites') return;
  clearTimeout(siteLookupTimer);
  const q = e.target.value.trim();
  siteLookupTimer = setTimeout(async () => {
    if (q.length < 2) return;
    const r = await api('api/sites', { q, limit: 20, hide_bg: false, categories: [], start: META.first_day || state.start });
    $('#ex-options').innerHTML = r.rows.map(s => `<option value="${esc(s.name)}">`).join('');
  }, 250);
};
$('#ex-go').onclick = () => { state.exTarget = $('#ex-target').value.trim(); changed(); };
$('#ex-target').onkeydown = e => { if (e.key === 'Enter') $('#ex-go').click(); };

renderers.explore = async seq => {
  $('#ex-kind').value = state.exKind; $('#ex-target').value = state.exTarget;
  fillExploreOptions();
  if (!state.exTarget) {
    $('#ex-kpis').innerHTML = '<div class="hint">Pick a category, service or site to see who uses it and when.</div>';
    ['ex-ts', 'ex-heat'].forEach(id => empty(id, 'Nothing selected')); $('#ex-persons').innerHTML = $('#ex-sites').innerHTML = '';
    return;
  }
  const m = state.metric, xf = exploreFilter();
  const [sum, ts, heat, persons, sites] = await Promise.all([
    api('api/summary', xf), api('api/timeseries', { ...xf, metric: m, split: 'person' }), api('api/heatmap', { ...xf, metric: m }),
    api('api/top', { ...xf, by: 'person', sort: m }), api('api/top', { ...xf, by: 'site', sort: m, limit: 50 }),
  ]);
  if (stale(seq)) return;
  kpiCards($('#ex-kpis'), sum.current, sum.previous, sum.days);
  ts.series.length ? chart('ex-ts', tsOption(ts, m, 'person')) : empty('ex-ts');
  chart('ex-heat', heatOption(heat, m));
  const maxP = Math.max(1, ...persons.rows.map(r => r[m]));
  table($('#ex-persons'), [
    { t: 'Person', f: r => `<span class="dot" style="background:${colorFor('person', r.key, r.name)}"></span>${esc(r.name)}` },
    { t: 'Time', n: 1, f: r => fmtMin(r.minutes) }, { t: 'Per day', n: 1, f: r => fmtMin(r.minutes / sum.days) },
    { t: 'Queries', n: 1, f: r => nf.format(r.queries) }, { t: '', f: r => `<div class="bar" style="width:${r[m] / maxP * 120}px"></div>` },
  ], persons.rows, r => { state.persons = [r.key]; buildFilters(); showTab('timeline'); });
  table($('#ex-sites'), [{ t: 'Site', k: 'name' }, { t: 'Service', k: 'service' },
    { t: 'Time', n: 1, f: r => fmtMin(r.minutes) }, { t: 'Queries', n: 1, f: r => nf.format(r.queries) }], sites.rows,
  r => explore('sites', r.key));
};

// ---------------------------------------------------------------- timeline
renderers.timeline = async seq => {
  if (!state.tlDay || state.tlDay > state.end || state.tlDay < state.start) state.tlDay = state.end;
  $('#tl-day').value = state.tlDay; $('#tl-split').value = state.tlSplit;
  const tl = await api('api/timeline', { day: state.tlDay, split: state.tlSplit, top: 20 });
  if (stale(seq)) return;
  if (!tl.available) return empty('tl-chart', 'Hour-level detail for this day has expired (retention).');
  if (!tl.rows.length) return empty('tl-chart', 'No activity on this day');
  const names = tl.rows.map(r => `${r.name}  ${fmtMin(r.minutes)}`);
  const data = [];
  tl.rows.forEach((r, i) => r.intervals.forEach(([a, b]) => data.push({ value: [i, a, b], itemStyle: { color: colorFor(state.tlSplit, r.key, r.name) } })));
  chart('tl-chart', {
    tooltip: { formatter: p => `${esc(tl.rows[p.value[0]].name)}<br>${new Date(p.value[1]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} – ${new Date(p.value[2]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` },
    grid: { left: 220, right: 20, top: 10, bottom: 30 },
    xAxis: { type: 'time', min: tl.start, max: tl.end, axisLabel: { formatter: '{HH}:{mm}' } },
    yAxis: { type: 'category', data: names, inverse: true, axisLabel: { width: 210, overflow: 'truncate' } },
    dataZoom: [{ type: 'inside', xAxisIndex: 0, filterMode: 'weakFilter' }],
    series: [{
      type: 'custom', encode: { x: [1, 2], y: 0 }, data,
      renderItem: (params, api) => {
        const y = api.value(0), s = api.coord([api.value(1), y]), e = api.coord([api.value(2), y]);
        const h = api.size([0, 1])[1] * 0.6;
        return { type: 'rect', shape: echarts.graphic.clipRectByRect({ x: s[0], y: s[1] - h / 2, width: Math.max(1, e[0] - s[0]), height: h },
          { x: params.coordSys.x, y: params.coordSys.y, width: params.coordSys.width, height: params.coordSys.height }), style: api.style() };
      },
    }],
  });
  charts['tl-chart'].getDom().style.height = Math.max(260, tl.rows.length * 30 + 60) + 'px';
  charts['tl-chart'].resize();
};
$('#tl-day').onchange = e => { state.tlDay = e.target.value; changed(); };
$('#tl-split').onchange = e => { state.tlSplit = e.target.value; changed(); };
$('#tl-prev').onclick = () => { state.tlDay = addDays(state.tlDay, -1); if (state.tlDay < state.start) { state.start = state.tlDay; state.preset = 'custom'; buildFilters(); } changed(); };
$('#tl-next').onclick = () => { state.tlDay = addDays(state.tlDay, 1); if (state.tlDay > state.end) { state.end = state.tlDay; state.preset = 'custom'; buildFilters(); } changed(); };

// ---------------------------------------------------------------- sites
const PAGE = 100;
async function setCategory(site, category, service) {
  await send('POST', 'api/rules', { pattern: site, category, service: service || null });
  toast(`${site} → ${category}. Re-categorizing history in the background.`);
  await loadMeta();
}
renderers.sites = async seq => {
  const [res, nw] = await Promise.all([
    api('api/sites', { sort: state.stSort, limit: PAGE, offset: state.stPage * PAGE }), api('api/new_sites', { limit: 100 }),
  ]);
  if (stale(seq)) return;
  const pages = Math.max(1, Math.ceil(res.total / PAGE));
  if (state.stPage >= pages) { state.stPage = 0; }
  $('#st-count').textContent = `${nf.format(res.total)} sites`;
  $('#st-page').textContent = ` ${state.stPage + 1} / ${pages} `;
  const catSelect = r => `<select data-site="${esc(r.name)}" data-svc="${esc(r.service || '')}" aria-label="Category of ${esc(r.name)}">${META.categories.map(c => `<option ${c === r.category ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select>`;
  const el = table($('#st-table'), [
    { t: 'Site', k: 'name', sort: 'name' }, { t: 'Category', f: catSelect }, { t: 'Service', k: 'service' },
    { t: 'Queries', n: 1, sort: 'queries', f: r => nf.format(r.queries) }, { t: 'Blocked', n: 1, sort: 'blocked', f: r => nf.format(r.blocked) },
    { t: 'Time', n: 1, sort: 'minutes', f: r => fmtMin(r.minutes) }, { t: 'Devices', n: 1, sort: 'devices', k: 'devices' },
    { t: 'First seen', sort: 'first_seen', f: r => fmtDate(r.first_seen) },
  ], res.rows, r => explore('sites', r.name));
  $$('th.sort', el).forEach(th => th.onclick = () => { state.stSort = th.dataset.sort; state.stPage = 0; changed(); });
  $$('select[data-site]', el).forEach(s => s.onchange = () => setCategory(s.dataset.site, s.value, s.dataset.svc));
  table($('#st-new'), [{ t: 'Site', k: 'name' }, { t: 'Category', f: r => catTag(r.category) }, { t: 'First seen', f: r => fmtDate(r.first_seen) },
    { t: 'By device', k: 'client' }, { t: 'Queries (all time)', n: 1, f: r => nf.format(r.queries) }], nw.rows, r => explore('sites', r.name));
};
$('#st-prev').onclick = () => { state.stPage = Math.max(0, state.stPage - 1); changed(); };
$('#st-next').onclick = () => { state.stPage += 1; changed(); };

// ---------------------------------------------------------------- dns
renderers.dns = async seq => {
  const d = await api('api/dns');
  if (stale(seq)) return;
  const pie = rows => ({ tooltip: { trigger: 'item', valueFormatter: v => nf.format(v) }, legend: { type: 'scroll', orient: 'vertical', right: 0, top: 'middle' },
    series: [{ type: 'pie', radius: ['40%', '72%'], center: ['35%', '50%'], label: { show: false }, data: rows.map(([name, value]) => ({ name, value })) }] });
  d.reasons.length ? chart('dn-reasons', pie(d.reasons)) : empty('dn-reasons');
  d.qtypes.length ? chart('dn-qtypes', hbarOption(d.qtypes.map(([name, v]) => ({ name, queries: v })), 'queries')) : empty('dn-qtypes');
  d.upstreams.length ? chart('dn-up', hbarOption(d.upstreams.map(([name, v]) => ({ name, queries: v })), 'queries')) : empty('dn-up');
  chart('dn-perf', {
    tooltip: { trigger: 'axis' }, legend: { top: 0 }, grid: { left: 50, right: 50, top: 30, bottom: 30 },
    xAxis: { type: 'category', data: d.days },
    yAxis: [{ type: 'value', name: 'ms' }, { type: 'value', max: 100, axisLabel: { formatter: '{value}%' } }],
    series: [
      { name: 'Avg latency (ms)', type: 'line', data: d.latency_ms, symbol: 'none', itemStyle: { color: PALETTE[0] } },
      { name: 'Cache hits %', type: 'line', yAxisIndex: 1, data: d.cache_rate.map(v => v == null ? null : +(v * 100).toFixed(1)), symbol: 'none', itemStyle: { color: PALETTE[4] } },
      { name: 'Blocked %', type: 'line', yAxisIndex: 1, data: d.block_rate.map(v => v == null ? null : +(v * 100).toFixed(1)), symbol: 'none', itemStyle: { color: PALETTE[2] } },
    ],
  });
};

// ---------------------------------------------------------------- settings
renderers.settings = async seq => {
  await loadMeta();
  const rules = await api('api/rules', null, {});
  if (stale(seq)) return;
  const pt = table($('#persons-table'), [
    { t: 'Name', f: p => `<input data-f="name" value="${esc(p.name)}" maxlength="64" aria-label="Name">` },
    { t: 'Color', f: p => `<input data-f="color" type="color" value="${esc(p.color || hashColor(p.name))}" aria-label="Color">` },
    { t: 'Devices', n: 1, f: p => META.clients.filter(c => c.person_id === p.id).length },
    { t: '', f: p => `<button data-del="${p.id}">Delete</button>` },
  ], META.persons);
  $$('tbody tr', pt).forEach((tr, i) => {
    const p = META.persons[i];
    if (!p) return;
    $$('input', tr).forEach(inp => inp.onchange = async () => {
      await send('PUT', `api/persons/${p.id}`, { name: $('[data-f=name]', tr).value, color: $('[data-f=color]', tr).value });
      toast('Saved'); await loadMeta(); buildFilters();
    });
  });
  $$('button[data-del]', pt).forEach(b => b.onclick = async () => {
    const p = META.persons.find(x => x.id === +b.dataset.del);
    if (!confirm(`Delete person "${p.name}"? Their devices become unassigned; no traffic data is deleted.`)) return;
    await send('DELETE', `api/persons/${p.id}`);
    state.persons = state.persons.filter(x => x !== p.id);
    await loadMeta(); buildFilters(); refresh();
  });

  const personOpts = c => `<option value="">— unassigned —</option>` + META.persons.map(p => `<option value="${p.id}" ${p.id === c.person_id ? 'selected' : ''}>${esc(p.name)}</option>`).join('');
  const clients = META.clients.slice().sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
  const ct = table($('#clients-table'), [
    { t: 'IP / ClientID', k: 'ip' }, { t: 'AdGuard name', k: 'name' },
    { t: 'Label', f: c => `<input data-f="label" value="${esc(c.label || '')}" placeholder="e.g. Anna's phone" maxlength="64" aria-label="Label">` },
    { t: 'Person', f: c => `<select data-f="person" aria-label="Person">${personOpts(c)}</select>` },
    { t: 'First seen', f: c => c.first_seen ? fmtDate(c.first_seen) : '<span class="hint">no queries yet</span>' },
    { t: 'Last seen', f: c => fmtDate(c.last_seen) },
  ], clients);
  $$('tbody tr', ct).forEach((tr, i) => {
    const c = clients[i];
    if (!c) return;
    $$('input,select', tr).forEach(inp => inp.onchange = async () => {
      const pid = $('[data-f=person]', tr).value;
      await send('PUT', `api/clients/${c.id}`, { label: $('[data-f=label]', tr).value, person_id: pid ? +pid : null });
      toast('Saved'); await loadMeta(); buildFilters();
    });
  });

  const counts = rules.counts || {};
  $('#rules-info').textContent = `Rules: ${counts.user || 0} yours, ${counts.builtin || 0} built-in, ${counts.adguard || 0} from AdGuard services.` +
    (rules.regroup_pending ? ` Re-categorizing ${rules.regroup_pending} days…` : '');
  const rt = table($('#rules-table'), [{ t: 'Pattern', k: 'pattern' }, { t: 'Category', f: r => catTag(r.category) }, { t: 'Service', k: 'service' },
    { t: '', f: r => `<button data-pat="${esc(r.pattern)}">Remove</button>` }], rules.rules);
  $$('button[data-pat]', rt).forEach(b => b.onclick = async () => {
    await send('DELETE', `api/rules/${encodeURIComponent(b.dataset.pat)}`); toast('Rule removed'); refresh();
  });
  $('#collector-info').textContent = JSON.stringify({ ...META.collector, adguard_url: META.adguard_url, timezone: META.timezone,
    data_from: META.first_day, hour_detail_since: META.hourly_since }, null, 2);
};
$('#person-form').onsubmit = async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await send('POST', 'api/persons', { name: fd.get('name'), color: fd.get('color') });
  e.target.reset(); toast('Person added'); await loadMeta(); buildFilters(); refresh();
};
$('#rule-form').onsubmit = async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await send('POST', 'api/rules', { pattern: fd.get('pattern'), category: fd.get('category'), service: fd.get('service') || null });
  e.target.reset(); toast('Rule saved; re-categorizing history'); refresh();
};

// ---------------------------------------------------------------- boot
(async () => {
  await loadMeta();
  if (state.preset !== 'custom' || !state.start) applyPreset();
  buildFilters();
  const linked = location.hash.slice(1);
  showTab(linked in renderers ? linked : state.tab in renderers ? state.tab : 'overview');
  addEventListener('hashchange', () => { const h = location.hash.slice(1); if (h in renderers && h !== state.tab) showTab(h); });
  setInterval(async () => {
    if (document.hidden) return;
    await loadMeta();
    if (['overview', 'people', 'timeline'].includes(state.tab) && state.end >= META.today) refresh();
  }, 120000);
})();
