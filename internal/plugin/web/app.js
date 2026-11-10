'use strict';
const $ = id => document.getElementById(id);
let host = null, state = null, timer, locked = false, authenticated = false, editingKey = false, session = 0, connectionID = '', observedConnectionID = '';
let filterMode = 'assign', pendingExclusion = '', excludeButtons = [], probeFailureOpened = false;
const filters = {assign:['filterAssign', '待变更'], all:['filterAll', '全部'], keep:['filterKeep', '保留'], skip:['filterSkip', '跳过']};
const probeFailures = {timeout:'连接超时', connect:'TCP 连接失败', socks_auth:'SOCKS 认证失败', socks:'SOCKS 握手失败', tls:'TLS 握手失败', unknown:'未知错误'};
function readCPAConnection() {
  try {
    const suffix = '/v0/resource/plugins/cpa-plugin-set-proxies/ui';
    if (!window.location.pathname.endsWith(suffix)) return null;
    const base = window.location.origin + window.location.pathname.slice(0, -suffix.length);
    const raw = window.localStorage.getItem('cli-proxy-auth');
    if (!raw) return null;
    const texts = [];
    const version = /^enc::(v[12])::/.exec(raw)?.[1];
    if (version) {
      const bytes = Uint8Array.from(atob(raw.slice(9)), ch => ch.charCodeAt(0));
      const salt = 'cli-proxy-api-webui::secure-storage';
      // Native CPA and Manager Plus use different v2 obfuscation salts.
      const keys = version === 'v1'
        ? [`${salt}|${window.location.host}|${navigator.userAgent}`]
        : [`${salt}|${window.location.host}`, `${salt}|v2|${window.location.host}`];
      for (const key of keys) {
        const mask = new TextEncoder().encode(key);
        texts.push(new TextDecoder().decode(bytes.map((b, i) => b ^ mask[i % mask.length])));
      }
    } else texts.push(raw);
    for (const text of texts) {
      let saved;
      try { saved = JSON.parse(text)?.state; } catch { continue; }
      if (typeof saved?.apiBase !== 'string' || typeof saved.managementKey !== 'string') continue;
      const key = saved.managementKey.trim();
      if (!key || /[\u0000-\u001f\u007f]/.test(key)) continue;
      const url = new URL(saved.apiBase.replace(/\/+$/, '').replace(/\/v(?:0|8)\/management$/, ''));
      if (url.username || url.password || url.search || url.hash) continue;
      if (url.origin + url.pathname.replace(/\/+$/, '') === base) return {base, key};
    }
  } catch {}
  return null;
}
const storedHost = {version:1, async request(path, body) {
  const before = readCPAConnection();
  if (!before || JSON.stringify(before) !== connectionID) return {status:401};
  if (!['/state', '/settings', '/scan', '/apply', '/cancel'].includes(path)) return {status:400};
  const response = await fetch(before.base + '/v0/management/plugins/cpa-plugin-set-proxies' + path, {
    method:body === undefined ? 'GET' : 'POST',
    headers:{Authorization:'Bearer ' + before.key, ...(body === undefined ? {} : {'Content-Type':'application/json'})},
    body:body === undefined ? undefined : JSON.stringify(body),
    credentials:'omit', redirect:'error', cache:'no-store', signal:AbortSignal.timeout(30000),
  });
  let data;
  try { data = await response.json(); } catch {}
  const after = readCPAConnection();
  return after?.base === before.base && after?.key === before.key ? {status:response.status, data} : {status:401};
}};
const active = () => ['scanning', 'applying', 'cancelling'].includes(state?.phase);
const phases = {idle:'空闲', scanning:'扫描中', ready:'可预览', applying:'应用中', cancelling:'正在取消', completed:'已完成', failed:'任务失败', cancelled:'已取消'};
const stages = {fetch:'下载代理', probe:'探测可用性', credentials:'读取凭证', complete:'处理完成', write:'写入凭证'};
const reasons = {'excluded or runtime-only':'已排除或仅运行时凭证','no physical file':'无物理文件','excluded or not a credential file':'已排除或非凭证文件','needs live proxy':'需要可用代理','live identity':'当前代理可用','external or explicit setting':'外部代理或显式设置'};
const resultLabels = {success:'成功', conflict:'冲突，未写入', failed:'失败', unknown:'结果不确定，请复核'};
const hostVars = ['--bg-primary', '--bg-secondary', '--bg-tertiary', '--text-primary', '--text-secondary', '--text-tertiary', '--border-color', '--primary-color'];
const details = {
  'Invalid JSON':'请求无效，JSON 格式错误。',
  'Invalid auto check interval':'自动巡检间隔须为 5–1440 分钟，或设为 0 关闭。',
  'Invalid settings or missing management key':'请在设置中填写管理密码并检查下载链接。',
  'Unable to verify CPA management password':'暂时无法验证管理密码，请稍后重试。',
  'Invalid or missing Webshare configuration':'Webshare 下载链接无效或尚未保存。',
  'Plugin is quiesced':'插件已暂停，请稍后重试。',
  'Task already running':'已有任务正在运行，请等待完成或取消任务。',
  'Plan unavailable or expired':'计划不可用或已过期，请重新扫描。',
  'Unable to save plugin settings':'无法保存设置，请重试。',
  'Unable to start scan':'无法启动扫描，请重试。',
  'Save settings before applying':'请先保存设置，再应用计划。',
  'Unable to read CPA listener configuration':'无法读取 CPA 监听配置。',
  'Proxy download plan not found':'下载服务返回 HTTP 404：找不到链接指定的 Webshare 套餐（Plan not found）。请在当前套餐重新生成下载链接并保存。',
  'Proxy download request invalid':'无法创建代理下载请求，请检查已保存的链接。',
  'Proxy download DNS failed':'服务器无法解析下载服务域名，请检查服务器 DNS。',
  'Proxy download TLS failed':'服务器无法验证下载服务的 TLS 证书，请检查服务器证书环境。',
  'Proxy download timed out':'服务器下载代理超时，请检查服务器到下载服务的连接。',
  'Proxy download network failed':'服务器下载代理时连接或读取失败，请检查服务器网络。',
  'Proxy download exceeds size limit':'下载内容超过 16 MiB 限制，已拒绝处理。',
  'Proxy list empty':'下载成功，但下载服务返回了空代理列表。',
  'Proxy list format invalid':'下载成功，但内容中没有有效的 host:port:username:password 格式代理。',
  'No live proxies':'没有可用代理，请检查代理状态后重新扫描。',
  'Credential listing failed':'无法获取凭证列表，请重新扫描。',
  'Invalid credential listing':'凭证列表格式无效，请检查后重新扫描。',
  'Credential read failed':'无法读取凭证，请检查后重新扫描。',
  'Credential physical path changed':'凭证文件路径已变更，请重新扫描。',
  'Ambiguous credential filename':'凭证文件名存在歧义，请检查同名文件。',
  'Unable to create plan':'无法创建计划，请重新扫描。',
  'Credential file changed; scan again':'凭证文件已变更，未写入，请重新扫描。',
  'Proxy setting changed; scan again':'代理设置已变更，未写入，请重新扫描。',
  'Invalid CPA listener configuration':'CPA 监听配置无效。',
  'Write result uncertain; scan again':'写入结果不确定，请复核并重新扫描。',
  'Updated':'代理已更新。',
  'CPA management authentication failed':'CPA 管理密码无效，请在设置中更换。',
  'CPA management rate limit reached':'CPA 管理请求达到速率限制，请稍后重试。',
  'CPA management redirect refused':'CPA 管理接口返回重定向，已拒绝跟随。',
  'CPA update rejected':'CPA 拒绝更新凭证，请检查后重试。',
};
function elementTheme(el) {
  if (!el) return '';
  for (const attr of ['data-theme', 'data-color-scheme', 'data-mode']) {
    const val = String(el.getAttribute?.(attr) ?? el[attr] ?? '').toLowerCase();
    if (val === 'dark') return 'dark';
    if (val === 'light' || val === 'white') return 'light';
  }
  const cls = typeof el.className === 'string' ? el.className : '';
  if (/\b(theme-dark|dark-mode|dark)\b/i.test(cls)) return 'dark';
  if (/\b(theme-light|light-mode|light|white)\b/i.test(cls)) return 'light';
  const scheme = String(el.style?.colorScheme ?? '').toLowerCase();
  return scheme === 'dark' || scheme === 'light' ? scheme : '';
}
function syncTheme() {
  const root = $('cpa-set-proxies');
  if (!root) return 'light';
  const docEl = document.documentElement;
  const isCpampBridge = docEl?.getAttribute?.('data-cpamp-plugin-host') === 'true' ||
    /\bcpamp-plugin-host\b/.test(docEl?.className || '');
  let parentDoc = null;
  try {
    if (window.parent && window.parent !== window && window.parent.document?.documentElement) {
      parentDoc = window.parent.document;
    }
  } catch {}
  let theme = '';
  for (let el = root.parentElement; el; el = el.parentElement) {
    if ((theme = elementTheme(el))) break;
  }
  if (!theme) theme = elementTheme(docEl) || elementTheme(document.body);
  if (parentDoc) {
    const parentEl = parentDoc.documentElement;
    if (!theme) theme = elementTheme(parentEl) || elementTheme(parentDoc.body) || 'light';
    if (isCpampBridge) {
      if (root.style?.removeProperty) for (const name of hostVars) root.style.removeProperty(name);
    } else if (root.style?.setProperty && typeof window.parent?.getComputedStyle === 'function') {
      const cs = window.parent.getComputedStyle(parentEl);
      for (const name of hostVars) {
        const val = cs?.getPropertyValue?.(name)?.trim() || '';
        if (val) root.style.setProperty(name, val);
        else root.style.removeProperty?.(name);
      }
    }
  } else if (isCpampBridge && root.style?.removeProperty) {
    for (const name of hostVars) root.style.removeProperty(name);
  }
  if (!theme) {
    theme = window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light';
  }
  root.setAttribute('data-theme', theme);
  return theme;
}
function knownMessage(value) {
  if (typeof value !== 'string') return '';
  if (Object.hasOwn(details, value)) return details[value];
  const http = /^Proxy download HTTP ([1-5][0-9]{2})$/.exec(value);
  return http ? '代理下载服务返回 HTTP ' + http[1] + '，未获得代理列表。' : '';
}
function message(text, phase = authenticated ? (state?.phase || 'idle') : 'unauth') {
  const el = $('status');
  el.textContent = text;
  el.className = 'csp-status-badge csp-phase-' + phase;
}
function controls() {
  const busy = locked || active();
  for (const id of ['url', 'excludes', 'save', 'editKey', 'managementKey', 'saveKey', 'cancelKey']) $(id).disabled = !authenticated || busy;
  $('autoEnabled').disabled = !authenticated || busy;
  $('autoMinutes').disabled = !authenticated || busy || !Boolean($('autoEnabled').checked);
  $('keyEditor').hidden = !editingKey;
  $('editKey').hidden = editingKey;
  $('editKey').textContent = state?.management_key_set ? '更换密码' : '设置密码';
  $('cancelKey').hidden = !state?.management_key_set;
  $('clearURL').disabled = !authenticated || busy || !state?.configured;
  $('scan').disabled = !authenticated || busy || !state?.configured;
  $('apply').disabled = !authenticated || busy || !state?.management_key_set || state?.preview_stale || state?.phase !== 'ready' || !state?.plan_id || !(state?.summary?.pending > 0);
  $('apply').textContent = state?.summary?.pending > 0 ? `应用变更 · ${state.summary.pending}` : '应用变更';
  for (const {button, name, excluded} of excludeButtons) {
    button.disabled = !authenticated || busy || !state?.management_key_set;
    button.textContent = pendingExclusion === name ? '保存中…' : excluded ? '取消排除' : '排除';
    button.title = !state?.management_key_set ? '请先在设置中保存管理密码' : '';
  }
  for (const [id] of Object.values(filters)) $(id).disabled = !authenticated;
  $('search').disabled = !authenticated;
  $('cancel').disabled = !authenticated || locked || !(active() || state?.plan_id) || state?.phase === 'cancelling';
  $('refresh').disabled = locked;
  $('apply').hidden = !authenticated || !state?.plan_id;
  $('cancel').hidden = !authenticated || !(active() || state?.plan_id);
  $('refresh').hidden = false;
}
function disconnect(text = '未读取到 CPA 登录信息，请在管理页面记住密码后重新打开插件。') {
  session++; host = null; connectionID = ''; authenticated = false; state = null; locked = false; editingKey = false;
  clearTimeout(timer);
  for (const id of ['url', 'excludes', 'managementKey']) $(id).value = '';
  filterMode = 'assign'; pendingExclusion = ''; excludeButtons = []; probeFailureOpened = false;
  $('search').value = '';
  for (const id of ['rows', 'results', 'probeRows']) $(id).replaceChildren();
  for (const id of ['filterBar', 'planNotice', 'previewTable', 'probePanel', 'emptyReset']) $(id).hidden = true;
  $('probePanel').open = false;
  $('previewTitle').textContent = '分配预览';
  $('emptyText').textContent = '扫描后显示分配预览';
  $('probeStats').textContent = ''; $('filterCount').textContent = '';
  $('confirm').close();
  $('configured').textContent = '';
  $('autoEnabled').checked = false; $('autoMinutes').value = '10';
  $('scheduleInfo').textContent = ''; $('scheduleInfo').hidden = true;
  $('keyStatus').textContent = '待读取';
  $('summary').textContent = ''; $('counts').textContent = '尚未应用';
  $('empty').hidden = false;
  $('settings').open = false;
  $('resultPanel').hidden = true;
  $('progress').hidden = true;
  $('progress').value = 0; $('progress').max = 1;
  message(text, 'unauth'); controls();
}
async function request(path, body) {
  const current = session;
  let response;
  try {
    response = await host.request(path, body);
  } catch { throw new Error(current === session ? '网络请求失败，请刷新状态后重试。' : ''); }
  if (current !== session) throw new Error('');
  if (response.status === 401 || response.status === 403) {
    disconnect('CPA 连接已失效，请刷新管理页面；后台任务继续运行。');
    throw new Error('');
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(knownMessage(response.data?.error) || '请求失败（HTTP ' + response.status + '），请刷新状态。');
  }
  if (body !== undefined) return;
  if (!response.data || typeof response.data !== 'object' || Array.isArray(response.data)) {
    throw new Error('服务器返回格式无效，请刷新状态。');
  }
  return response.data;
}
function normalizeExcludes(value) {
  const names = Array.isArray(value) ? value : value.split(/\r?\n/);
  return [...new Set(names.map(name => name.trim()).filter(Boolean))];
}
function cells(tr, values) {
  for (const value of values) {
    const td = document.createElement('td'); td.textContent = value || '—'; tr.append(td);
  }
}
function renderPreview() {
  const rows = state.rows || [], query = $('search').value.trim().toLowerCase();
  const visible = rows.filter(row => (filterMode === 'all' || row.action === filterMode) && row.name.toLowerCase().includes(query));
  $('previewTitle').textContent = state.preview_stale ? '上次预览' : '分配预览';
  $('planNotice').hidden = !state.preview_stale;
  $('filterBar').hidden = !rows.length;
  for (const [mode, [id, label]] of Object.entries(filters)) {
    const count = mode === 'all' ? rows.length : rows.filter(row => row.action === mode).length;
    $(id).textContent = `${label} ${count}`;
    $(id).setAttribute('aria-pressed', String(mode === filterMode));
  }
  $('filterCount').textContent = `显示 ${visible.length} / ${rows.length}`;
  $('empty').hidden = Boolean(visible.length);
  $('previewTable').hidden = !visible.length;
  $('emptyReset').hidden = !rows.length || (!query && filterMode === 'all');
  $('emptyReset').textContent = query ? '清除筛选与搜索' : `查看全部 ${rows.length} 项`;
  $('emptyText').textContent = !rows.length ? '扫描后显示分配预览' : query ? '没有匹配的凭证' : filterMode === 'assign' ? '当前无需变更' : '当前筛选下无凭证';
  const focusedName = document.activeElement?.getAttribute('data-exclude-name');
  $('rows').replaceChildren(); excludeButtons = [];
  for (const row of visible) {
    const tr = document.createElement('tr');
    if (['assign', 'keep', 'skip'].includes(row.action)) tr.className = row.action;
    const action = row.action === 'assign' && !row.current_endpoint ? '分配' : {keep:'保留',assign:'替换',skip:'跳过'}[row.action] || '未知';
    cells(tr, [row.name, row.current_endpoint, row.proposed_endpoint, action, reasons[row.reason] || '其他原因']);
    const td = document.createElement('td'), excluded = (state.excludes || []).includes(row.name);
    if (row.excludable || excluded) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'csp-btn-inline';
      button.setAttribute('data-exclude-name', row.name);
      button.setAttribute('aria-label', (excluded ? '取消排除 ' : '排除 ') + row.name);
      button.onclick = () => toggleExclude(row.name);
      excludeButtons.push({button, name:row.name, excluded}); td.append(button);
    } else td.textContent = '—';
    tr.append(td); $('rows').append(tr);
  }
  controls();
  if (focusedName) excludeButtons.find(item => item.name === focusedName)?.button.focus({preventScroll:true});
}
function renderProbes() {
  const probes = state.probes || [], checked = probes.filter(probe => probe.checked);
  const alive = checked.filter(probe => probe.alive).length;
  $('probePanel').hidden = !probes.length;
  $('probeStats').textContent = `已检测 ${checked.length} / ${probes.length} · 可用 ${alive} · 失败 ${checked.length - alive}`;
  if (!probes.length) { $('probePanel').open = false; probeFailureOpened = false; }
  if (state.error === 'No live proxies' && !probeFailureOpened) {
    $('probePanel').open = true; probeFailureOpened = true;
  }
  $('probeRows').replaceChildren();
  for (const probe of probes) {
    const tr = document.createElement('tr');
    tr.className = !probe.checked ? 'csp-probe-pending' : probe.alive ? 'csp-probe-alive' : 'csp-probe-failed';
    const status = !probe.checked ? active() ? '待检测' : '未完成' : probe.alive ? '可用' : '不可用';
    const category = Object.hasOwn(probeFailures, probe.category) ? probeFailures[probe.category] : '未知错误';
    const duration = probe.checked && Number.isFinite(probe.duration_ms) && probe.duration_ms >= 0 ? probe.duration_ms === 0 ? '<1 ms' : `${probe.duration_ms} ms` : '—';
    cells(tr, [probe.endpoint, status, duration, probe.checked ? `${probe.attempts}/3` : '—', probe.checked && !probe.alive ? category : '—']);
    $('probeRows').append(tr);
  }
}
async function toggleExclude(name) {
  if (!authenticated || locked || active() || !state?.management_key_set) return;
  const current = session, excluded = (state.excludes || []).includes(name);
  const update = names => excluded ? names.filter(value => value !== name) : [...new Set([...names, name])];
  const next = update(normalizeExcludes(state.excludes || []));
  pendingExclusion = name;
  await command('/settings', {excludes:next}, false, () => {
    $('excludes').value = update(normalizeExcludes($('excludes').value)).join('\n');
    state = {...state, excludes:next, plan_id:'', preview_stale:true, phase:'idle', stage:'', error:''};
    render();
  });
  if (current !== session) return;
  const focus = document.activeElement;
  const restoreFocus = !focus || focus === document.body || focus.getAttribute('data-exclude-name') === name;
  pendingExclusion = ''; controls();
  if (restoreFocus) excludeButtons.find(item => item.name === name)?.button.focus({preventScroll:true});
}
for (const [mode, [id]] of Object.entries(filters)) $(id).onclick = () => {
  if (!authenticated) return;
  filterMode = mode; renderPreview();
};
$('search').oninput = () => { if (authenticated) renderPreview(); };
$('emptyReset').onclick = () => {
  if (!authenticated || !state) return;
  filterMode = 'all'; $('search').value = ''; renderPreview(); $('search').focus();
};
function formatTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(value) || Number.isNaN(Date.parse(value))) return '';
  return new Intl.DateTimeFormat('zh-CN', {month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false}).format(new Date(value));
}
const autoInterval = value => Number.isInteger(value) && value >= 5 ? value : 0;
const autoDraft = () => Boolean($('autoEnabled').checked) ? Number($('autoMinutes').value.trim()) : 0;
function render() {
  const interval = autoInterval(state.auto_interval_minutes);
  const lastAt = formatTimestamp(state.last_check_at), nextAt = formatTimestamp(state.next_check_at);
  $('scheduleInfo').hidden = !(interval > 0 || lastAt);
  $('scheduleInfo').textContent = interval > 0 || lastAt ? [interval ? `自动巡检：每 ${interval} 分钟` : '自动巡检：已关闭', lastAt ? `上次检查：${lastAt}` : (interval ? '上次检查：待运行' : ''), interval && nextAt ? `下次检查：${nextAt}` : ''].filter(Boolean).join(' · ') : '';
  $('configured').textContent = (state.configured ? '链接已保存' : '未保存下载链接') + ' · ' + (state.management_key_set ? '密码已设置' : '未设置管理密码');
  $('keyStatus').textContent = state.error === 'CPA management authentication failed' ? '需要更新' : state.management_key_set ? '已设置' : '未设置';
  const s = state.summary || {};
  const phase = state.phase === 'ready' && !(s.pending > 0) ? '无需变更' : phases[state.phase] || '未知状态';
  message([phase, stages[state.stage], state.error ? knownMessage(state.error) || '请检查配置或重新扫描。' : ''].filter(Boolean).join(' · '), state.phase || 'idle');
  $('progress').hidden = !active();
  $('progress').max = Math.max(1, state.total || 0); $('progress').value = state.done || 0;
  $('summary').textContent = `进度 ${state.done || 0}/${state.total || 0} · 代理 ${s.proxies || 0} · 可用 ${s.alive || 0} · 凭证 ${s.credentials || 0} · 保留 ${s.kept || 0} · 待替换 ${s.pending || 0} · 外部 ${s.external || 0} · 排除 ${s.excluded || 0}`;
  renderPreview();
  renderProbes();
  const results = state.results || [];
  $('resultPanel').hidden = !(results.length || state.phase === 'applying' || state.phase === 'completed');
  const count = status => results.filter(result => result.status === status).length;
  $('counts').textContent = state.phase === 'completed' && !results.length && !(s.pending > 0)
    ? '本轮无需替换代理'
    : `已处理 ${results.length} · 成功 ${count('success')} · 冲突 ${count('conflict')} · 失败 ${count('failed')} · 不确定 ${count('unknown')} · 未处理 ${Math.max(0, (s.pending || 0) - results.length)}`;
  $('results').replaceChildren();
  for (const result of results) {
    const li = document.createElement('li');
    li.className = 'csp-result-' + (result.status || 'unknown');
    li.textContent = result.name + '：' + [resultLabels[result.status] || '未知结果，请复核', knownMessage(result.message)].filter(Boolean).join(' · ');
    $('results').append(li);
  }
  controls();
}
function poll() {
  clearTimeout(timer);
  if (authenticated && (active() || autoInterval(state?.auto_interval_minutes))) timer = setTimeout(() => refresh(), active() ? 1200 : 15000);
}
async function refresh(initial = false) {
  clearTimeout(timer);
  if (!host) return connectHost();
  const current = session, first = initial || !authenticated;
  try {
    const next = await request('/state');
    if (current !== session) return;
    const keyInvalid = next.error === 'CPA management authentication failed';
    if (first) {
      $('excludes').value = (next.excludes || []).join('\n');
      editingKey = !next.management_key_set || keyInvalid;
      $('settings').open = !next.configured || editingKey;
    } else {
      if (JSON.stringify(normalizeExcludes($('excludes').value)) === JSON.stringify(normalizeExcludes(state?.excludes || []))) {
        $('excludes').value = (next.excludes || []).join('\n');
      }
      if (keyInvalid && state?.error !== next.error) {
        editingKey = true;
        $('settings').open = true;
      }
    }
    const savedInterval = autoInterval(state?.auto_interval_minutes);
    const autoUnchanged = Boolean($('autoEnabled').checked) === (savedInterval > 0) && $('autoMinutes').value === (savedInterval ? String(savedInterval) : '10');
    if (first || autoUnchanged) {
      const interval = autoInterval(next.auto_interval_minutes);
      $('autoEnabled').checked = interval > 0;
      $('autoMinutes').value = interval ? String(interval) : '10';
    }
    state = next; authenticated = true;
    render();
  } catch (error) {
    if (current !== session) return;
    if (error.message) message(error.message, 'failed');
    controls();
  }
  if (current === session) poll();
}
async function command(path, body, saved = false, onSaved) {
  if (!authenticated || locked) return;
  const current = session;
  locked = true; controls(); clearTimeout(timer);
  if (path === '/cancel') message('正在停止，等待当前操作结束；已写入不会回滚', 'cancelling');
  try {
    await request(path, body);
    if (current !== session) return;
    if (onSaved) onSaved();
    if (saved) $('url').value = '';
    if (body?.management_key) {
      $('managementKey').value = '';
      editingKey = false;
    }
    await refresh();
    if (current === session && saved && authenticated) $('settings').open = !state?.configured || !state?.management_key_set;
  } catch (error) { if (error.message) message(error.message, 'failed'); }
  finally { if (current === session) { locked = false; controls(); poll(); } }
}
async function connectHost() {
  const bridge = window.cpaPluginHost;
  const connection = readCPAConnection();
  observedConnectionID = JSON.stringify(connection);
  const next = bridge?.version === 1 && typeof bridge.request === 'function' ? bridge : connection ? storedHost : null;
  const id = next === storedHost ? JSON.stringify(connection) : '';
  if (next === host && id === connectionID) return;
  disconnect();
  if (!next) return;
  host = next; connectionID = id; locked = true; controls();
  const current = session;
  await refresh(true);
  if (current === session) { locked = false; controls(); }
}
window.addEventListener('cpa-plugin-host-ready', connectHost);
window.addEventListener('storage', event => { if (event.key === 'cli-proxy-auth' || event.key === null) return connectHost(); });
window.addEventListener('focus', connectHost);
// A storage event is not sent to the document that writes it (the parent iframe host).
setInterval(() => {
  if ((host === storedHost || !host) && JSON.stringify(readCPAConnection()) !== observedConnectionID) return connectHost();
}, 1000);
$('refresh').onclick = () => refresh();
function save(clear) {
  if ($('save').disabled || (clear && $('clearURL').disabled)) return;
  const body = {webshare_url:clear ? '' : $('url').value.trim(), excludes:$('excludes').value.split(/\r?\n/).map(x => x.trim()).filter(Boolean), clear_webshare_url:clear};
  if (!clear) {
    const minutes = autoDraft();
    if ($('autoEnabled').checked && (!$('autoMinutes').value.trim() || !Number.isInteger(minutes) || minutes < 5 || minutes > 1440)) {
      message(details['Invalid auto check interval'], 'failed'); return;
    }
    body.auto_interval_minutes = minutes;
    if (editingKey && $('managementKey').value.trim()) body.management_key = $('managementKey').value.trim();
  }
  return command('/settings', body, true, () => {
    state = {...state, auto_interval_minutes:clear ? 0 : body.auto_interval_minutes};
    $('autoEnabled').checked = !clear && body.auto_interval_minutes > 0;
    $('autoMinutes').value = !clear && body.auto_interval_minutes ? String(body.auto_interval_minutes) : '10';
  });
}
$('autoEnabled').onchange = () => {
  if ($('autoEnabled').checked && (!$('autoMinutes').value.trim() || Number($('autoMinutes').value) < 5)) $('autoMinutes').value = '10';
  controls();
};
$('save').onclick = () => save(false);
$('clearURL').onclick = () => save(true);
$('editKey').onclick = () => {
  if ($('editKey').disabled) return;
  editingKey = true; controls(); $('managementKey').focus();
};
$('cancelKey').onclick = () => {
  if ($('cancelKey').disabled) return;
  $('managementKey').value = ''; editingKey = false; controls();
};
$('saveKey').onclick = () => {
  if ($('saveKey').disabled) return;
  const key = $('managementKey').value.trim();
  if (!key) { message('请输入 CPA 管理密码。', 'failed'); return; }
  return command('/settings', {management_key:key});
};
$('scan').onclick = () => {
  if ($('scan').disabled) return;
  probeFailureOpened = false;
  return command('/scan', {});
};
$('cancel').onclick = () => { if (!$('cancel').disabled) return command('/cancel', {}); };
$('apply').onclick = () => {
  if ($('apply').disabled) return;
  $('confirmDescription').textContent = `将更新 ${state.summary.pending} 个凭证，应用范围为完整计划，不受当前筛选影响。关闭页面或退出不会中止任务。取消仅停止后续写入，已完成的变更不会回滚。`;
  $('confirm').showModal();
};
$('confirmNo').onclick = () => $('confirm').close();
$('confirmYes').onclick = () => {
  $('confirm').close();
  if (!$('apply').disabled) return command('/apply', {plan_id:state.plan_id});
};
if (typeof MutationObserver === 'function') {
  const obs = new MutationObserver(syncTheme);
  const opts = {attributes:true, attributeFilter:['data-theme', 'data-color-scheme', 'data-mode', 'data-cpamp-plugin-host', 'class', 'style']};
  if (document.documentElement) obs.observe(document.documentElement, opts);
  if (document.body) obs.observe(document.body, opts);
  try {
    if (window.parent && window.parent !== window && window.parent.document?.documentElement) {
      obs.observe(window.parent.document.documentElement, opts);
      if (window.parent.document.body) obs.observe(window.parent.document.body, opts);
    }
  } catch {}
}
window.matchMedia?.('(prefers-color-scheme: dark)')?.addEventListener?.('change', syncTheme);
disconnect();
syncTheme();
connectHost();
