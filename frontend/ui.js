(() => {
'use strict';
const C = window.APP_CONFIG;
document.title = C.title;
if (C.theme) document.documentElement.style.setProperty('--primary', C.theme);
const $ = (s, r = document) => r.querySelector(s);
const h = (tag, attrs, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
};
let token = sessionStorage.getItem('token');
let user = JSON.parse(sessionStorage.getItem('user') || 'null');
const label = s => String(s).replace(/_/g, ' ');
const fmt = {
  money: v => (v == null ? '—' : (v / 100).toLocaleString(undefined, { style: 'currency', currency: C.currency || 'USD' })),
  datetime: v => (v ? String(v).replace('T', ' ').slice(0, 16) : '—'),
  bool: v => (v ? 'Yes' : 'No'),
};
function toast(msg, kind) {
  const t = h('div', { class: 'toast ' + (kind || '') }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 4500);
}
async function api(path, { method = 'GET', body } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method, body: body ? JSON.stringify(body) : undefined,
      headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    });
  } catch { throw { message: 'Network error. Check your connection and try again.' }; }
  let json = null;
  try { json = await res.json(); } catch { /* non-JSON */ }
  if (res.status === 401 && token) { signedOut(); throw { message: 'Session expired. Please sign in again.' }; }
  if (!res.ok) throw { status: res.status, message: (json && json.error && json.error.message) || 'Request failed', details: json && json.error && json.error.details };
  return json;
}
function signedOut() { token = null; user = null; sessionStorage.clear(); renderAuth(); }
const can = roles => !roles || roles.includes(user.role);

/* ---------- forms ---------- */
async function loadOptions(spec, row) {
  if (spec.options_from) {
    const r = await api(spec.options_from.path);
    return r.data.map(o => ({ value: o[spec.options_from.value || 'id'], label: o[spec.options_from.label || 'name'] }));
  }
  const ch = typeof spec.choices === 'function' ? spec.choices(row) : (spec.choices || []);
  return ch.map(c => (typeof c === 'object' ? c : { value: c, label: label(c) }));
}
function control(spec, value, opts, id) {
  let el;
  const t = spec.type || 'text';
  if (t === 'textarea') el = h('textarea', { rows: 3, maxlength: spec.max });
  else if (t === 'select') {
    el = h('select', {}, spec.required ? null : h('option', { value: '' }, '—'), (opts || []).map(o => h('option', { value: o.value }, o.label)));
  } else {
    const type = { number: 'number', money: 'number', date: 'date', datetime: 'datetime-local', password: 'password', email: 'email', checkbox: 'checkbox' }[t] || 'text';
    el = h('input', { type, step: t === 'money' ? '0.01' : (t === 'number' ? '1' : null), min: t === 'money' ? '0' : spec.min, max: spec.max && t !== 'text' ? spec.max : null,
      maxlength: t === 'text' ? spec.max : null, autocomplete: t === 'password' ? 'new-password' : 'off' });
  }
  if (id) el.id = id;
  if (spec.required && t !== 'checkbox') el.required = true;
  if (t === 'checkbox') el.checked = !!value;
  else if (value != null) el.value = t === 'money' ? (value / 100).toFixed(2) : value;
  return el;
}
function readControl(spec, el) {
  const t = spec.type || 'text';
  if (t === 'checkbox') return el.checked;
  if (el.value === '') return null;
  if (t === 'number') return Number(el.value);
  if (t === 'money') return Math.round(parseFloat(el.value) * 100);
  return el.value;
}
function itemsControl(spec, optsMap) {
  const tbody = h('tbody'), rows = [];
  const add = () => {
    const els = spec.subfields.map(sf => { const e = control(sf, null, optsMap.get(sf)); e.setAttribute('aria-label', sf.label); return e; });
    const tr = h('tr', {}, els.map(e => h('td', {}, e)), h('td', {}, h('button', { type: 'button', class: 'btn small', onclick: () => { rows.splice(rows.findIndex(r => r.tr === tr), 1); tr.remove(); } }, 'Remove')));
    rows.push({ tr, els }); tbody.append(tr);
  };
  for (let i = 0; i < (spec.minRows || 1); i++) add();
  const el = h('div', { class: 'items' }, h('table', {}, h('thead', {}, h('tr', {}, spec.subfields.map(s => h('th', {}, s.label)), h('th'))), tbody),
    h('button', { type: 'button', class: 'btn small', onclick: add }, '+ Add line'));
  return { el, get: () => rows.map(r => Object.fromEntries(spec.subfields.map((sf, i) => [sf.key, readControl(sf, r.els[i])]))) };
}
async function formDialog({ title, fields, row, submitLabel, onSubmit, intro }) {
  fields = fields.filter(f => !f.roles || f.roles.includes(user.role));
  const all = fields.flatMap(f => [f, ...(f.subfields || [])]).filter(f => f.type === 'select');
  const optsMap = new Map();
  try { await Promise.all(all.map(async s => optsMap.set(s, await loadOptions(s, row)))); } catch (e) { toast(e.message, 'bad'); return; }
  const ctl = new Map(), errEls = new Map();
  const form = h('form', {});
  for (const f of fields) {
    const id = 'f_' + f.key;
    let c;
    if (f.type === 'items') c = itemsControl(f, optsMap);
    else { const e = control(f, row ? row[f.key] : f.default, optsMap.get(f), id); c = { el: e, get: () => readControl(f, e) }; }
    const er = h('div', { class: 'err', id: id + '_e', role: 'alert' });
    if (f.type !== 'items') c.el.setAttribute('aria-describedby', id + '_e');
    ctl.set(f, c); errEls.set(f.key, er);
    form.append(f.type === 'checkbox' ? h('label', { class: 'inline' }, c.el, f.label) : [h('label', { for: id }, f.label + (f.required ? ' *' : '')), c.el], er);
  }
  const formErr = h('div', { class: 'err', role: 'alert' });
  const submit = h('button', { class: 'btn primary', type: 'submit' }, submitLabel || 'Save');
  const dlg = h('dialog', { 'aria-labelledby': 'dlgt' }, h('h2', { id: 'dlgt' }, title), intro ? h('p', { class: 'hint' }, intro) : null, form);
  form.append(formErr, h('div', { class: 'form-actions' }, h('button', { type: 'button', class: 'btn', onclick: () => dlg.close() }, 'Cancel'), submit));
  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    errEls.forEach(e => (e.textContent = '')); formErr.textContent = '';
    const payload = {};
    for (const f of fields) payload[f.key] = ctl.get(f).get();
    submit.disabled = true;
    try { await onSubmit(payload); dlg.close(); }
    catch (e) {
      submit.disabled = false;
      const d = e.details || {};
      let shown = false;
      for (const [k, m] of Object.entries(d)) if (errEls.has(k)) { errEls.get(k).textContent = m; shown = true; }
      if (!shown || !e.details) formErr.textContent = e.message;
      else formErr.textContent = 'Please fix the highlighted fields.';
    }
  });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg); dlg.showModal();
}

function secretDialog(key) {
  const inp = h('input', { readonly: true, value: key, 'aria-label': 'Agent API key', onfocus: e => e.target.select() });
  const dlg = h('dialog', { 'aria-labelledby': 'sk' }, h('h2', { id: 'sk' }, 'Agent API key'),
    h('p', { class: 'hint' }, 'Copy this key now. It is shown only once and cannot be recovered.'), inp,
    h('div', { class: 'form-actions' }, h('button', { class: 'btn primary', onclick: () => dlg.close() }, 'I have copied it')));
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg); dlg.showModal(); inp.select();
}
/* ---------- views ---------- */
function cell(col, row) {
  const v = row[col.key];
  if (col.render) return col.render(row);
  if (col.type === 'badge') return v == null ? '—' : h('span', { class: 'badge tone-' + ((C.tones || {})[v] || 'grey') }, label(v));
  if (col.type && fmt[col.type]) return fmt[col.type](v);
  return v == null || v === '' ? '—' : String(v);
}
function resourceView(res) {
  const st = { page: 1, q: '', sort: '', order: 'desc', f: {} };
  const holder = h('div', {}), wrap = h('div', {});
  const filterEls = {};
  const reload = () => { st.page = 1; load(); };
  let timer;
  const search = res.search ? h('input', { type: 'search', class: 'grow', placeholder: 'Search…', 'aria-label': 'Search ' + res.label,
    oninput: e => { clearTimeout(timer); timer = setTimeout(() => { st.q = e.target.value; reload(); }, 300); } }) : null;
  const toolbar = h('div', { class: 'toolbar' }, search);
  for (const f of res.filters || []) {
    const sel = h('select', { 'aria-label': 'Filter by ' + f.label, onchange: e => { st.f[f.key] = e.target.value; reload(); } }, h('option', { value: '' }, 'All ' + f.label.toLowerCase()),
      (f.choices || []).map(c => h('option', { value: c }, label(c))));
    filterEls[f.key] = sel; toolbar.append(sel);
  }
  if (res.write && can(res.write) && !res.noCreate)
    toolbar.append(h('button', { class: 'btn primary', onclick: () => formDialog({ title: 'New ' + res.singular, fields: res.fields, submitLabel: 'Create',
      onSubmit: async p => { const r = await api('/api/' + res.name, { method: 'POST', body: p }); toast(res.singular + ' created'); if (r.data && r.data.api_key) secretDialog(r.data.api_key); load(); } }) }, '+ New ' + res.singular));
  async function load() {
    holder.replaceChildren(h('div', { class: 'state' }, 'Loading…'));
    const q = new URLSearchParams({ page: st.page, per_page: 10 });
    if (st.q) q.set('q', st.q);
    if (st.sort) { q.set('sort', st.sort); q.set('order', st.order); }
    Object.entries(st.f).forEach(([k, v]) => v && q.set(k, v));
    let r;
    try { r = await api('/api/' + res.name + '?' + q); }
    catch (e) { holder.replaceChildren(h('div', { class: 'state' }, e.message, ' ', h('button', { class: 'btn small', onclick: load }, 'Retry'))); return; }
    if (!r.data.length) { holder.replaceChildren(h('div', { class: 'card empty' }, st.q || Object.values(st.f).some(Boolean) ? 'No matching ' + res.label.toLowerCase() + '.' : 'No ' + res.label.toLowerCase() + ' yet.')); return; }
    const acts = row => [
      ...(res.actions || []).filter(a => can(a.roles) && (!a.when || a.when(row))).map(a => h('button', { class: 'btn small', onclick: () => runAction(a, row) }, a.label)),
      res.write && can(res.write) && !res.noEdit ? h('button', { class: 'btn small', onclick: () => formDialog({ title: 'Edit ' + res.singular, fields: (res.editFields || res.fields), row, submitLabel: 'Save',
        onSubmit: async p => { await api('/api/' + res.name + '/' + row.id, { method: 'PUT', body: p }); toast('Saved'); load(); } }) }, 'Edit') : null,
      res.del && can(res.del) ? h('button', { class: 'btn small danger', onclick: async () => { if (!confirm('Delete this ' + res.singular.toLowerCase() + '?')) return;
        try { await api('/api/' + res.name + '/' + row.id, { method: 'DELETE' }); toast('Deleted'); load(); } catch (e) { toast(e.message, 'bad'); } } }, 'Delete') : null,
    ];
    const hasActs = (res.actions || []).length || (res.write && !res.noEdit) || res.del;
    const th = c => h('th', { scope: 'col', 'aria-sort': st.sort === c.key ? (st.order === 'asc' ? 'ascending' : 'descending') : null },
      c.sortable ? h('button', { onclick: () => { st.order = st.sort === c.key && st.order === 'desc' ? 'asc' : 'desc'; st.sort = c.key; load(); } }, c.label + (st.sort === c.key ? (st.order === 'asc' ? ' ▲' : ' ▼') : '')) : c.label);
    const table = h('table', {}, h('caption', { class: 'skip' }, res.label), h('thead', {}, h('tr', {}, res.columns.map(th), hasActs ? h('th', { scope: 'col' }, 'Actions') : null)),
      h('tbody', {}, r.data.map(row => h('tr', {}, res.columns.map(c => h('td', {}, cell(c, row))), hasActs ? h('td', { class: 'actions' }, acts(row)) : null))));
    const m = r.meta;
    holder.replaceChildren(h('div', { class: 'tablewrap' }, table), h('div', { class: 'pager' }, h('span', {}, `${m.total} total · page ${m.page} of ${m.pages}`),
      h('button', { class: 'btn small', disabled: m.page <= 1, onclick: () => { st.page--; load(); } }, 'Previous'),
      h('button', { class: 'btn small', disabled: m.page >= m.pages, onclick: () => { st.page++; load(); } }, 'Next')));
  }
  function runAction(a, row) {
    const exec = async body => {
      if (!a.fields && a.confirm && !confirm(a.confirm)) return;
      const r = await api(a.path(row), { method: a.method || 'POST', body: { ...(a.body ? a.body(row) : {}), ...(body || {}) } });
      toast(a.label + ': done'); if (r.data && r.data.api_key) secretDialog(r.data.api_key); load();
    };
    if (a.fields) formDialog({ title: a.label, fields: a.fields.map(f => ({ ...f })), row, submitLabel: a.label, onSubmit: exec });
    else exec().catch(e => toast(e.message, 'bad'));
  }
  wrap.append(h('h1', {}, res.label), toolbar, holder);
  load();
  return wrap;
}
async function dashboardView() {
  const wrap = h('div', {}, h('h1', {}, 'Dashboard')), body = h('div', {}, h('div', { class: 'state' }, 'Loading…'));
  wrap.append(body);
  try {
    const { data } = await api('/api/stats');
    body.replaceChildren(h('div', { class: 'cards' }, data.cards.map(c => h('div', { class: 'card stat t-' + (c.tone || '') }, h('div', { class: 'v' }, c.format === 'money' ? fmt.money(c.value) : c.value), h('div', { class: 'l' }, c.label)))),
      h('div', { class: 'bars' }, (data.breakdowns || []).map(b => {
        const max = Math.max(1, ...b.items.map(i => i.value));
        return h('section', { class: 'card' }, h('h2', {}, b.title), b.items.length ? b.items.map(i => {
          const fill = h('div', { class: 'bar-fill' }); fill.style.width = (i.value / max * 100) + '%';
          return h('div', { class: 'bar-row' }, h('span', {}, label(i.label)), h('div', { class: 'bar-track' }, fill), h('b', {}, i.value));
        }) : h('p', { class: 'empty' }, 'No data yet.'));
      })));
  } catch (e) { body.replaceChildren(h('div', { class: 'state' }, e.message)); }
  return wrap;
}
const CORE = [
  { name: 'users', label: 'Users', singular: 'User', read: ['admin'], write: ['admin'], noCreate: true, search: true,
    filters: [{ key: 'role', label: 'Roles', choices: C.roles }],
    columns: [{ key: 'name', label: 'Name', sortable: true }, { key: 'email', label: 'Email' }, { key: 'role', label: 'Role', type: 'badge' }, { key: 'active', label: 'Active', type: 'bool' }, { key: 'created_at', label: 'Joined', sortable: true }],
    fields: [{ key: 'name', label: 'Name', required: true, max: 100 }, { key: 'role', label: 'Role', type: 'select', required: true, choices: C.roles }, { key: 'active', label: 'Active', type: 'checkbox' }],
    actions: [{ label: 'Reset password', roles: ['admin'], path: r => `/api/users/${r.id}/reset-password`, fields: [{ key: 'password', label: 'New password', type: 'password', required: true }] }] },
  { name: 'audit', label: 'Audit log', singular: 'Entry', read: C.auditRoles || ['admin'], search: true, filters: [{ key: 'entity', label: 'Entities', choices: C.auditEntities || [] }],
    columns: [{ key: 'created_at', label: 'When (UTC)' }, { key: 'user_email', label: 'User' }, { key: 'action', label: 'Action', type: 'badge' }, { key: 'entity', label: 'Entity' }, { key: 'entity_id', label: 'ID' }, { key: 'detail', label: 'Detail' }] },
];
function routes() {
  const list = [{ name: 'dashboard', label: 'Dashboard' }, ...C.resources, ...CORE];
  return list.filter(r => r.name === 'dashboard' || can(r.read));
}
function renderApp() {
  const rs = routes();
  const main = h('main', { id: 'main', tabindex: '-1' });
  const nav = h('nav', { class: 'side', 'aria-label': 'Primary' });
  const show = async () => {
    const name = location.hash.slice(2) || 'dashboard';
    const r = rs.find(x => x.name === name) || rs[0];
    nav.querySelectorAll('button').forEach(b => { if (b.dataset.r === r.name) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
    main.replaceChildren(r.name === 'dashboard' ? await dashboardView() : resourceView(r));
  };
  rs.forEach(r => nav.append(h('button', { 'data-r': r.name, onclick: () => { location.hash = '#/' + r.name; } }, r.label)));
  const top = h('header', { class: 'top' }, h('div', { class: 'brand' }, C.title), h('div', { class: 'tag' }, C.tagline),
    h('span', {}, `${user.name} · ${label(user.role)}`),
    h('button', { class: 'btn', onclick: async () => { try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* already invalid */ } signedOut(); } }, 'Sign out'));
  $('#root').replaceChildren(h('div', { class: 'shell' }, top, nav, main));
  window.onhashchange = show; show();
}
function renderAuth() {
  window.onhashchange = null;
  let mode = 'login';
  const box = h('div', { class: 'card' });
  const draw = () => {
    const reg = mode === 'register', msg = h('div', { class: 'err', role: 'alert' });
    const f = {
      name: reg ? h('input', { id: 'a_name', required: true, maxlength: 100, autocomplete: 'name' }) : null,
      email: h('input', { id: 'a_email', type: 'email', required: true, autocomplete: 'username' }),
      pw: h('input', { id: 'a_pw', type: 'password', required: true, minlength: reg ? 10 : null, autocomplete: reg ? 'new-password' : 'current-password' }),
    };
    const btn = h('button', { class: 'btn primary', type: 'submit', style: null }, reg ? 'Create account' : 'Sign in');
    const form = h('form', {}, reg ? [h('label', { for: 'a_name' }, 'Full name'), f.name] : null, h('label', { for: 'a_email' }, 'Email'), f.email,
      h('label', { for: 'a_pw' }, 'Password'), f.pw, reg ? h('p', { class: 'hint' }, 'At least 10 characters, with letters and digits.') : null, msg, h('div', { class: 'form-actions' }, btn));
    form.addEventListener('submit', async e => {
      e.preventDefault(); msg.textContent = ''; btn.disabled = true;
      try {
        if (reg) {
          await api('/api/auth/register', { method: 'POST', body: { name: f.name.value, email: f.email.value, password: f.pw.value } });
          toast('Account created. You can sign in now.'); mode = 'login'; draw(); return;
        }
        const r = await api('/api/auth/login', { method: 'POST', body: { email: f.email.value, password: f.pw.value } });
        token = r.data.token; user = r.data.user; sessionStorage.setItem('token', token); sessionStorage.setItem('user', JSON.stringify(user));
        renderApp();
      } catch (er) { msg.textContent = (er.details && Object.values(er.details).join(' ')) || er.message; btn.disabled = false; }
    });
    const tab = (m, t) => h('button', { type: 'button', class: 'btn' + (mode === m ? ' primary' : ''), 'aria-pressed': String(mode === m), onclick: () => { mode = m; draw(); } }, t);
    box.replaceChildren(h('div', { class: 'tabs' }, tab('login', 'Sign in'), tab('register', 'Register')), form,
      C.demoHint ? h('p', { class: 'hint' }, C.demoHint) : null);
  };
  draw();
  $('#root').replaceChildren(h('main', { class: 'auth', id: 'main' }, h('h1', {}, C.title), h('p', { class: 'hint', style: null }, C.tagline), box));
}
(async () => {
  if (token) { try { const r = await api('/api/auth/me'); user = r.data; renderApp(); return; } catch { /* fall through */ } }
  renderAuth();
})();
})();
