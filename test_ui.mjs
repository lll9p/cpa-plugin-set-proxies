import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, existsSync} from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./internal/plugin/web/app.js', import.meta.url), 'utf8');
const base = '/v0/management/plugins/cpa-plugin-set-proxies';
const initial = () => ({configured:true, management_key_set:true, excludes:['saved.json'], phase:'idle', stage:'', done:0, total:0, summary:{pending:0}, rows:[], results:[]});
const ready = () => ({...initial(), phase:'ready', plan_id:'plan-1', summary:{pending:5}, rows:[{name:'a.json', current_endpoint:'old:80', proposed_endpoint:'new:80', action:'assign', reason:'needs live proxy'}]});
const pageURL = 'https://cpa.example/v0/resource/plugins/cpa-plugin-set-proxies/ui';
const userAgent = 'CPA UI tests / 浏览器';
const auth = (apiBase = 'https://cpa.example', managementKey = 'browser-secret') => JSON.stringify({state:{apiBase, managementKey}, version:0});
function encodedAuth(raw, version, managerPlus = false, location = pageURL) {
  const host = new URL(location).host;
  const salt = 'cli-proxy-api-webui::secure-storage';
  const mask = new TextEncoder().encode(version === 'v1' ? `${salt}|${host}|${userAgent}` : managerPlus ? `${salt}|v2|${host}` : `${salt}|${host}`);
  const bytes = new TextEncoder().encode(raw).map((b, i) => b ^ mask[i % mask.length]);
  return `enc::${version}::` + btoa(String.fromCharCode(...bytes));
}
function browserGlobals(storedAuth, location = pageURL) {
  const storage = {raw:storedAuth, reads:[], writes:[]};
  const globals = {URL, TextEncoder, TextDecoder, atob, btoa, AbortSignal, location:new URL(location), navigator:{userAgent}, localStorage:{
    getItem(key) { storage.reads.push(key); assert.equal(key, 'cli-proxy-auth'); return storage.raw ?? null; },
  }};
  for (const method of ['setItem', 'removeItem', 'clear']) globals.localStorage[method] = (...args) => {
    storage.writes.push({method, args});
    throw new Error('Browser storage must remain read-only');
  };
  for (const name of ['sessionStorage', 'indexedDB']) Object.defineProperty(globals, name, {get() { throw new Error('Browser storage accessed: ' + name); }});
  globals.window = globals;
  return {globals, storage};
}
function readConnection(storedAuth, location = pageURL) {
  const {globals, storage} = browserGlobals(storedAuth, location);
  const context = vm.createContext(globals);
  const start = source.indexOf('function readCPAConnection()');
  assert.notEqual(start, -1);
  vm.runInContext(source.slice(start, source.indexOf('\nconst storedHost', start)), context);
  const connection = vm.runInContext('readCPAConnection()', context);
  assert.deepEqual(storage.writes, []);
  return connection && JSON.parse(JSON.stringify(connection));
}
function harness({storedAuth, location = pageURL} = {}) {
  const elements = new Map(), requests = [], timers = new Map(), intervals = new Map(), events = new Map();
  const {globals, storage} = browserGlobals(storedAuth, location);
  let nextTimer = 0;
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      value:'', disabled:false, hidden:false, textContent:'', children:[], open:false, attributes:new Map(),
      getAttribute(name) { return this.attributes.get(name) ?? null; },
      setAttribute(name, value) { this.attributes.set(name, String(value)); },
      addEventListener(name, handler) { this[name] = handler; },
      replaceChildren(...children) { this.children = children; },
      append(child) { this.children.push(child); },
      showModal() { this.open = true; },
      close() { this.open = false; },
      focus() { this.focused = true; },
    });
    return elements.get(id);
  };
  const h = {element, requests, timers, intervals, storage, state:initial(), status:200, postStatus:202, error:'Invalid JSON'};
  const reply = async (path, options) => {
    requests.push({path, ...options});
    if (h.reply) return h.reply(path, options);
    const status = options.method === 'GET' ? h.status : h.postStatus;
    return {status, data:status >= 400 ? {error:h.error} : options.method === 'GET' ? structuredClone(h.state) : undefined};
  };
  const bridge = {version:1, request:(path, body) => reply(base + path, {method:body === undefined ? 'GET' : 'POST', body:body === undefined ? undefined : JSON.stringify(body)})};
  Object.assign(globals, {
    document:{getElementById:element, createElement:() => ({textContent:'', children:[], append(child) { this.children.push(child); }})},
    setTimeout:fn => { const id = ++nextTimer; timers.set(id, fn); return id; },
    clearTimeout:id => timers.delete(id),
    setInterval:(fn, delay) => { const id = ++nextTimer; intervals.set(id, {fn, delay}); return id; },
    clearInterval:id => intervals.delete(id),
    fetch:async (path, options) => {
      const response = await reply(path, options);
      return {status:response.status, json:async () => response.data};
    },
    addEventListener:(name, handler) => {
      if (!events.has(name)) events.set(name, []);
      events.get(name).push(handler);
    },
  });
  Object.defineProperty(globals.document, 'cookie', {get() { throw new Error('Cookies read'); }, set() { throw new Error('Cookies written'); }});
  globals.window = globals;
  h.context = vm.createContext(globals);
  h.ready = vm.runInContext(source, h.context);
  h.fireEvent = async (name, event = {}) => {
    for (const handler of events.get(name) || []) await handler(event);
  };
  h.setAuth = async (raw, event = 'storage') => {
    storage.raw = raw;
    if (event) await h.fireEvent(event, {key:'cli-proxy-auth'});
  };
  h.checkAuth = async () => {
    assert.equal(intervals.size, 1);
    for (const {fn, delay} of intervals.values()) { assert.equal(delay, 1000); await fn(); }
  };
  h.connect = async (next = bridge) => {
    globals.cpaPluginHost = next;
    await h.fireEvent('cpa-plugin-host-ready');
  };
  h.detach = async () => {
    delete globals.cpaPluginHost;
    await h.fireEvent('cpa-plugin-host-ready');
  };
  h.tick = async () => {
    assert.equal(timers.size, 1);
    const [id, fn] = timers.entries().next().value;
    timers.delete(id); await fn();
  };
  return h;
}
function hostRequests(h) {
  for (const request of h.requests) {
    assert.ok(request.path.startsWith(base + '/'));
    assert.equal(request.headers, undefined, 'plugin never handles authentication headers');
    assert.ok(['GET', 'POST'].includes(request.method));
  }
}

test('host connection replaces plugin login, loads excludes once and preserves drafts', async () => {
  const h = harness(), $ = h.element;
  assert.equal(h.requests.length, 0, 'public page never obtains access by itself');
  assert.equal($('scan').disabled, true);
  assert.match($('status').textContent, /CPA.*管理页面/);
  await h.connect();
  assert.equal($('excludes').value, 'saved.json');
  $('excludes').value = 'draft.json';
  await $('refresh').onclick();
  assert.equal($('excludes').value, 'draft.json');
  assert.equal($('scan').disabled, false);
  assert.ok(!$('status').textContent.endsWith(' · '));
  hostRequests(h);
});

test('save posts settings and excludes, blank preserves URL, explicit clear, success clears secret input', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  $('url').value = 'https://example.com/secret';
  $('excludes').value = ' a.json \n\n b.json\r\n';
  await $('save').onclick();
  let post = h.requests.find(r => r.path.endsWith('/settings'));
  assert.deepEqual(JSON.parse(post.body), {webshare_url:'https://example.com/secret', excludes:['a.json', 'b.json'], clear_webshare_url:false});
  assert.equal($('url').value, '');
  assert.equal($('excludes').value, ' a.json \n\n b.json\r\n');
  await $('save').onclick();
  post = h.requests.filter(r => r.path.endsWith('/settings')).at(-1);
  assert.equal(JSON.parse(post.body).webshare_url, '');
  await $('clearURL').onclick();
  post = h.requests.filter(r => r.path.endsWith('/settings')).at(-1);
  assert.equal(JSON.parse(post.body).clear_webshare_url, true);
  $('url').value = 'keep-on-error'; h.postStatus = 400;
  await $('save').onclick();
  assert.equal($('url').value, 'keep-on-error');
  assert.match($('status').textContent, /请求无效/);
  hostRequests(h);
});

test('scan requires saved URL, sends only empty plugin request, disables settings and polls without overwriting drafts', async () => {
  const h = harness(), $ = h.element;
  h.state.configured = false; await h.connect();
  await $('scan').onclick();
  assert.equal(h.requests.filter(r => r.method === 'POST').length, 0);
  h.state.configured = true; await $('refresh').onclick();
  $('excludes').value = 'unsaved.json'; $('url').value = 'unsaved-secret';
  h.state.phase = 'scanning'; h.state.stage = 'probe';
  await $('scan').onclick();
  const scan = h.requests.find(r => r.path.endsWith('/scan'));
  assert.deepEqual(JSON.parse(scan.body), {});
  for (const id of ['url', 'excludes', 'save', 'clearURL', 'scan', 'apply']) assert.equal($(id).disabled, true, id);
  await h.tick();
  assert.equal($('excludes').value, 'unsaved.json');
  assert.equal($('url').value, 'unsaved-secret');
  h.state = ready(); await h.tick();
  assert.equal(h.timers.size, 0);
  assert.equal($('apply').disabled, false);
  assert.equal($('rows').children[0].className, 'assign');
  assert.equal($('empty').hidden, true);
  hostRequests(h);
});

test('apply polls backend results including unknown and unprocessed; browser never downloads or PATCHes credentials', async () => {
  const h = harness(), $ = h.element;
  h.state = ready(); await h.connect();
  $('apply').onclick(); assert.equal($('confirm').open, true);
  assert.match($('confirmDescription').textContent, /更新 5 个凭证/);
  h.state.phase = 'applying'; h.state.stage = 'write';
  await $('confirmYes').onclick();
  const apply = h.requests.find(r => r.path.endsWith('/apply'));
  assert.deepEqual(JSON.parse(apply.body), {plan_id:'plan-1'});
  assert.equal($('apply').disabled, true);
  assert.equal(h.timers.size, 1);
  h.state.results = [{name:'a.json', status:'success'}, {name:'b.json', status:'conflict'}, {name:'c.json', status:'failed'}, {name:'d.json', status:'unknown', message:'untrusted detail'}];
  await h.tick();
  assert.match($('counts').textContent, /已处理 4 · 成功 1 · 冲突 1 · 失败 1 · 不确定 1 · 未处理 1/);
  assert.equal($('results').children.length, 4);
  assert.doesNotMatch($('results').children[3].textContent, /untrusted/);
  h.state.phase = 'completed'; await h.tick();
  assert.equal(h.timers.size, 0);
  assert.equal($('apply').disabled, true);
  assert.ok(h.requests.every(r => /\/(state|apply)$/.test(r.path)));
  hostRequests(h);
});

test('apply eligibility is owned by backend state, not a consumed-plan browser guard', async () => {
  const h = harness(), $ = h.element;
  h.state = ready(); h.state.summary.pending = 0; await h.connect();
  assert.equal($('apply').disabled, true);
  h.state.summary.pending = 1; h.state.plan_id = ''; await $('refresh').onclick();
  assert.equal($('apply').disabled, true);
  h.state.plan_id = 'plan-1'; await $('refresh').onclick();
  await $('confirmYes').onclick();
  assert.equal($('apply').disabled, false, 'unchanged ready state remains authoritative');
});

test('explicit cancellation calls backend and polls cancelling state; host disconnect never cancels', async () => {
  const h = harness(), $ = h.element;
  h.state = {...ready(), phase:'applying'}; await h.connect();
  h.state.phase = 'cancelling'; await $('cancel').onclick();
  assert.deepEqual(JSON.parse(h.requests.find(r => r.path.endsWith('/cancel')).body), {});
  assert.equal($('cancel').disabled, true);
  assert.equal(h.timers.size, 1);
  h.state.phase = 'cancelled'; await h.tick();
  assert.equal(h.timers.size, 0);
  const cancels = h.requests.filter(r => r.path.endsWith('/cancel')).length;
  await h.detach();
  assert.equal(h.requests.filter(r => r.path.endsWith('/cancel')).length, cancels);
});

for (const mode of ['detach', '401', '403']) test(`${mode} clears UI, stops polling and never cancels backend task`, async () => {
  const h = harness(), $ = h.element;
  h.state = {...ready(), phase:'applying', results:[{name:'a.json', status:'success'}]};
  await h.connect();
  $('url').value = 'private-url'; $('managementKey').value = 'private-password';
  if (mode === 'detach') await h.detach();
  else { h.status = Number(mode); await h.tick(); }
  for (const id of ['url', 'excludes', 'managementKey']) assert.equal($(id).value, '');
  for (const id of ['rows', 'results']) assert.equal($(id).children.length, 0);
  assert.equal($('summary').textContent, '');
  assert.equal($('scan').disabled, true);
  assert.equal(h.timers.size, 0);
  assert.equal(vm.runInContext('host', h.context), null);
  const before = h.requests.length;
  await $('refresh').onclick();
  assert.equal(h.requests.length, before + (mode === 'detach' ? 0 : 1), 'refresh may reconnect to the existing bridge');
  assert.equal(h.requests.some(r => r.path.endsWith('/cancel')), false);
  h.status = 200;
  await h.connect();
  assert.equal(h.timers.size, 1, 'reconnecting resumes watching the backend task');
});

test('host disconnect during a state request cannot restore data or restart polling', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  let release;
  h.reply = () => new Promise(resolve => { release = resolve; });
  const pending = $('refresh').onclick();
  await h.detach();
  release({status:200, data:{...ready(), phase:'applying'}});
  await pending;
  assert.equal($('rows').children.length, 0);
  assert.equal($('scan').disabled, true);
  assert.equal(h.timers.size, 0);
});

test('errors never expose raw server text or secrets', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  h.reply = async () => ({status:500, data:{error:'private-key'}});
  await $('scan').onclick();
  assert.match($('status').textContent, /HTTP 500/);
  assert.doesNotMatch($('status').textContent, /private/);
  h.state = {...initial(), phase:'failed', error:'private-url'};
  h.reply = null; await $('refresh').onclick();
  assert.doesNotMatch($('status').textContent, /private/);
});

test('static UI has labelled dialog and controls, no CSP meta or obsolete embedded runner', () => {
  const html = readFileSync(new URL('./internal/plugin/web/index.html', import.meta.url), 'utf8');
  const ui = readFileSync(new URL('./internal/plugin/ui.go', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /Content-Security-Policy|\/\*LOGIC\*\//);
  assert.doesNotMatch(ui, /logic\.js|LOGIC/);
  assert.doesNotMatch(source, /\.(?:setItem|removeItem|clear)\s*\(|\b(sessionStorage|indexedDB)\b|document\.cookie|beforeunload|pagehide/);
  assert.equal(existsSync(new URL('./internal/plugin/web/logic.js', import.meta.url)), false);
  assert.doesNotMatch(html, /id="(?:login|loginButton|logout|syncKey)"/);
  assert.doesNotMatch(source, /CPA Manager Plus|同步密钥/);
  assert.match(html, /label for="managementKey"/);
  assert.match(html, /id="managementKey" type="password" autocomplete="new-password"/);
  assert.match(source, /getItem\(['"]cli-proxy-auth['"]\)/);
  assert.match(html, /aria-labelledby="confirmTitle"/);
  assert.match(html, /关闭页面或退出不会中止任务/);
});

test('ready plan can be cancelled and cancel immediately explains a pending stop', async () => {
  const h = harness(), $ = h.element;
  h.state = ready(); await h.connect();
  assert.equal($('cancel').disabled, false);
  let release;
  h.reply = (path) => {
    assert.equal(path, base + '/cancel');
    return new Promise(resolve => { release = resolve; });
  };
  const stopping = $('cancel').onclick();
  assert.equal($('status').textContent, '正在停止，等待当前操作结束；已写入不会回滚');
  assert.equal($('cancel').disabled, true);
  assert.equal($('apply').disabled, true);
  assert.equal($('save').disabled, true);
  assert.equal(h.timers.size, 0);
  h.reply = null; h.state = {...initial(), phase:'cancelled', plan_id:''};
  release({status:200});
  await stopping;
  assert.equal($('status').textContent, '已取消');
  assert.equal($('cancel').disabled, true);
  assert.equal(h.requests.filter(r => r.path.endsWith('/cancel')).length, 1);
});

test('ready with no pending changes explicitly says no changes and cannot apply an empty plan', async () => {
  const h = harness(), $ = h.element;
  h.state = {...ready(), plan_id:'', stage:'complete', summary:{pending:0}};
  await h.connect();
  assert.equal($('status').textContent, '无需变更 · 处理完成');
  assert.equal($('apply').disabled, true);
  assert.equal($('cancel').disabled, true);
  const before = h.requests.length;
  await $('confirmYes').onclick();
  assert.equal(h.requests.length, before);
  h.state = {...initial(), phase:'completed', stage:'complete'};
  await $('refresh').onclick();
  assert.equal($('status').textContent, '已完成 · 处理完成');
});

test('409 distinguishes a running task from an unavailable or expired plan', async () => {
  const h = harness(), $ = h.element;
  await h.connect(); h.postStatus = 409;
  h.error = 'Task already running'; await $('scan').onclick();
  assert.equal($('status').textContent, '已有任务正在运行，请等待完成或取消任务。');
  h.error = 'Plan unavailable or expired'; await $('scan').onclick();
  assert.equal($('status').textContent, '计划不可用或已过期，请重新扫描。');
});

test('state errors distinguish download, no live proxies, credential listing and read failures without duplicate failure labels', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  const failures = [
    ['Proxy download plan not found', '下载服务返回 HTTP 404：找不到链接指定的 Webshare 套餐（Plan not found）。请在当前套餐重新生成下载链接并保存。'],
    ['Proxy download HTTP 404', '代理下载服务返回 HTTP 404，未获得代理列表。'],
    ['Proxy download HTTP 403', '代理下载服务返回 HTTP 403，未获得代理列表。'],
    ['Proxy download HTTP 429', '代理下载服务返回 HTTP 429，未获得代理列表。'],
    ['Proxy download HTTP 503', '代理下载服务返回 HTTP 503，未获得代理列表。'],
    ['Proxy list empty', '下载成功，但下载服务返回了空代理列表。'],
    ['Proxy list format invalid', '下载成功，但内容中没有有效的 host:port:username:password 格式代理。'],
    ['Proxy download request invalid', '无法创建代理下载请求，请检查已保存的链接。'],
    ['Proxy download DNS failed', '服务器无法解析下载服务域名，请检查服务器 DNS。'],
    ['Proxy download TLS failed', '服务器无法验证下载服务的 TLS 证书，请检查服务器证书环境。'],
    ['Proxy download timed out', '服务器下载代理超时，请检查服务器到下载服务的连接。'],
    ['Proxy download network failed', '服务器下载代理时连接或读取失败，请检查服务器网络。'],
    ['Proxy download exceeds size limit', '下载内容超过 16 MiB 限制，已拒绝处理。'],
    ['No live proxies', '没有可用代理，请检查代理状态后重新扫描。'],
    ['Credential listing failed', '无法获取凭证列表，请重新扫描。'],
    ['Credential read failed', '无法读取凭证，请检查后重新扫描。'],
    ['Invalid credential listing', '凭证列表格式无效，请检查后重新扫描。'],
    ['Credential physical path changed', '凭证文件路径已变更，请重新扫描。'],
    ['Ambiguous credential filename', '凭证文件名存在歧义，请检查同名文件。'],
    ['Unable to create plan', '无法创建计划，请重新扫描。'],
    ['CPA management authentication failed', 'CPA 管理密码无效，请在设置中更换。'],
  ];
  for (const [error, expected] of failures) {
    h.state = {...initial(), phase:'failed', error};
    await $('refresh').onclick();
    assert.equal($('status').textContent, '任务失败 · ' + expected);
  }
  h.state = {...initial(), phase:'idle', error:''}; await $('refresh').onclick();
  assert.equal($('status').textContent, '空闲');
});

test('result details distinguish reads, changed files, changed proxies, auth failures and rejected writes', async () => {
  const h = harness(), $ = h.element;
  const results = [
    ['failed', 'Credential read failed', '无法读取凭证'],
    ['conflict', 'Credential file changed; scan again', '凭证文件已变更'],
    ['conflict', 'Proxy setting changed; scan again', '代理设置已变更'],
    ['failed', 'CPA management authentication failed', 'CPA 管理密码无效'],
    ['failed', 'CPA update rejected', 'CPA 拒绝更新凭证'],
    ['failed', 'CPA management rate limit reached', '速率限制'],
    ['failed', 'CPA management redirect refused', '已拒绝跟随'],
    ['failed', 'Invalid CPA listener configuration', 'CPA 监听配置无效'],
    ['unknown', 'Write result uncertain; scan again', '请复核并重新扫描'],
    ['success', 'Updated', '代理已更新'],
    ['unknown', 'private-url', '结果不确定，请复核'],
  ];
  h.state = {...initial(), phase:'completed', results:results.map(([status, message], i) => ({name:i + '.json', status, message}))};
  await h.connect();
  for (const [i, [, , expected]] of results.entries()) assert.ok($('results').children[i].textContent.includes(expected));
  assert.equal($('results').children.at(-1).textContent, '10.json：结果不确定，请复核');
  assert.doesNotMatch($('results').children.map(li => li.textContent).join(' '), /private-url/);
});

test('unknown or malformed errors use only HTTP or state/status fallback, including inherited object keys', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  for (const error of ['private-key https://private-url', 'Proxy download HTTP 404 https://private-url', 'Proxy download HTTP 999', 'Proxy download HTTP 40', 'constructor', '__proto__', {secret:'private-key'}, null]) {
    h.postStatus = 409; h.error = error;
    await $('scan').onclick();
    assert.equal($('status').textContent, '请求失败（HTTP 409），请刷新状态。');
    h.state = {...initial(), phase:'failed', error, results:[{name:'a.json', status:'failed', message:error}]};
    await $('refresh').onclick();
    assert.equal($('status').textContent, error ? '任务失败 · 请检查配置或重新扫描。' : '任务失败');
    assert.equal($('results').children[0].textContent, 'a.json：失败');
  }
  h.reply = async () => ({status:502, data:'private-parser-error'});
  await $('scan').onclick();
  assert.equal($('status').textContent, '请求失败（HTTP 502），请刷新状态。');
});

test('settings, progress, apply controls and results appear only in the relevant state', async () => {
  const h = harness(), $ = h.element;
  h.state = {...initial(), configured:false};
  await h.connect();
  assert.equal($('settings').open, true, 'first setup expands automatically');
  assert.equal($('apply').hidden, true);
  assert.equal($('cancel').hidden, true);
  assert.equal($('resultPanel').hidden, true);
  assert.equal($('progress').hidden, true);
  h.state.configured = true;
  await $('save').onclick();
  assert.equal($('settings').open, false, 'saved settings collapse');
  $('settings').open = true;
  $('url').value = 'draft';
  h.state.phase = 'scanning';
  await $('refresh').onclick();
  assert.equal($('settings').open, true, 'polling does not change disclosure state');
  assert.equal($('url').value, 'draft');
  assert.equal($('progress').hidden, false);
  assert.equal($('cancel').hidden, false);
  h.state = ready();
  await $('refresh').onclick();
  assert.equal($('apply').hidden, false);
  assert.equal($('resultPanel').hidden, true);
  assert.equal($('progress').hidden, true);
  h.state.phase = 'applying';
  await $('refresh').onclick();
  assert.equal($('resultPanel').hidden, false);
  await h.detach();
  assert.equal($('settings').open, false);
  assert.equal($('resultPanel').hidden, true);
  assert.equal($('progress').hidden, true);
  assert.equal($('apply').hidden, true);
  assert.equal($('refresh').hidden, false, 'refresh remains available to reconnect');
});

test('theme syncs from host html, same-origin parent (including explicit light without data-theme), and standalone media fallback', () => {
  const css = readFileSync(new URL('./internal/plugin/web/style.css', import.meta.url), 'utf8');
  assert.match(css, /#cpa-set-proxies/);
  assert.doesNotMatch(css, /(^|\})\s*(:root|body|main|section|h1|h2|p|label|button|input)\s*\{/);

  const h = harness(), root = h.element('cpa-set-proxies');
  const syncTheme = vm.runInContext('syncTheme', h.context);
  let systemDark = true;
  h.context.window.matchMedia = () => ({matches:systemDark});
  h.context.document.body = {children:[root, {tagName:'SCRIPT'}]};
  root.parentElement = h.context.document.body;
  assert.equal(syncTheme(), 'dark', 'standalone follows system dark');
  systemDark = false;
  assert.equal(syncTheme(), 'light', 'standalone follows system light');

  systemDark = true;
  const parentDocEl = {'data-theme':'', getAttribute(k) { return this[k]; }};
  h.context.window.parent = {
    document:{documentElement:parentDocEl, body:{}},
    getComputedStyle:() => ({getPropertyValue:k => k === '--bg-primary' ? '#f0eee8' : ''}),
  };
  const props = new Map();
  root.style = {setProperty:(k, v) => props.set(k, v), removeProperty:k => props.delete(k)};
  assert.equal(syncTheme(), 'light', 'same-origin parent without data-theme is explicit light even when OS is dark');
  assert.equal(root.getAttribute('data-theme'), 'light');
  assert.equal(props.get('--bg-primary'), '#f0eee8');

  parentDocEl['data-theme'] = 'dark';
  assert.equal(syncTheme(), 'dark', 'same-origin parent dark theme');
  parentDocEl['data-theme'] = 'white';
  assert.equal(syncTheme(), 'light', 'same-origin parent white theme maps to light');

  h.context.document.documentElement = {
    'data-cpamp-plugin-host':'true',
    'data-theme':'dark',
    getAttribute(k) { return this[k]; },
  };
  assert.equal(syncTheme(), 'dark', 'cpamp bridge dark theme');
  assert.equal(props.size, 0, 'cpamp bridge relies on injected stylesheet rather than inline style copies');
});


test('missing password opens settings; saving it preserves unrelated drafts and clears its input', async () => {
  const h = harness(), $ = h.element;
  h.state = {...ready(), management_key_set:false};
  await h.connect();
  assert.equal($('settings').open, true);
  assert.equal($('keyStatus').textContent, '未设置');
  assert.equal($('keyEditor').hidden, false);
  assert.equal($('cancelKey').hidden, true);
  assert.equal($('apply').disabled, true);
  $('url').value = 'draft-url'; $('excludes').value = 'draft.json';
  await $('saveKey').onclick();
  assert.equal(h.requests.filter(r => r.method === 'POST').length, 0);
  $('managementKey').value = ' new-cpa-secret ';
  h.state = initial();
  await $('saveKey').onclick();
  const request = h.requests.find(r => r.method === 'POST');
  assert.equal(request.path, base + '/settings');
  assert.deepEqual(JSON.parse(request.body), {management_key:'new-cpa-secret'});
  assert.equal($('url').value, 'draft-url');
  assert.equal($('excludes').value, 'draft.json');
  assert.equal($('managementKey').value, '');
  assert.equal($('keyEditor').hidden, true);
  assert.equal($('keyStatus').textContent, '已设置');
  h.state.phase = 'scanning'; await $('refresh').onclick();
  const before = h.requests.length;
  await $('editKey').onclick();
  await $('saveKey').onclick();
  assert.equal(h.requests.length, before, 'password changes are disabled during a task');
});

test('saved password stays hidden and is never sent by ordinary settings updates', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  assert.equal($('settings').open, false);
  assert.equal($('keyEditor').hidden, true);
  assert.equal($('managementKey').value, '');
  assert.equal($('editKey').textContent, '更换密码');
  $('editKey').onclick();
  assert.equal($('keyEditor').hidden, false);
  assert.equal($('managementKey').focused, true);
  $('managementKey').value = 'discarded-secret';
  $('cancelKey').onclick();
  assert.equal($('managementKey').value, '');
  assert.equal($('keyEditor').hidden, true);
  await $('save').onclick();
  const body = JSON.parse(h.requests.find(r => r.method === 'POST').body);
  assert.equal(Object.hasOwn(body, 'management_key'), false);
});

test('first setup saves the password with settings and clears both secret fields', async () => {
  const h = harness(), $ = h.element;
  h.state = {...initial(), configured:false, management_key_set:false};
  await h.connect();
  $('managementKey').value = 'new-cpa-secret';
  $('url').value = 'https://example.com/private';
  h.state = initial();
  await $('save').onclick();
  const body = JSON.parse(h.requests.find(r => r.method === 'POST').body);
  assert.equal(body.management_key, 'new-cpa-secret');
  assert.equal(body.webshare_url, 'https://example.com/private');
  assert.equal($('managementKey').value, '');
  assert.equal($('url').value, '');
  assert.equal($('keyEditor').hidden, true);
  assert.equal($('settings').open, false);
});

test('invalid password stays editable without resetting the panel connection or drafts', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  $('editKey').onclick();
  $('managementKey').value = 'wrong-password';
  $('url').value = 'url-draft'; $('excludes').value = 'draft.json';
  h.postStatus = 422; h.error = 'CPA management authentication failed';
  await $('saveKey').onclick();
  assert.match($('status').textContent, /管理密码无效/);
  assert.equal($('managementKey').value, 'wrong-password');
  assert.equal($('url').value, 'url-draft');
  assert.equal($('excludes').value, 'draft.json');
  assert.equal($('keyEditor').hidden, false);
  assert.equal($('saveKey').disabled, false);
  assert.equal($('scan').disabled, false);
  assert.equal(vm.runInContext('authenticated', h.context), true);
  h.postStatus = 502; h.error = 'Unable to verify CPA management password';
  await $('saveKey').onclick();
  assert.match($('status').textContent, /暂时无法验证管理密码/);
  assert.equal($('managementKey').value, 'wrong-password');
});

test('clearing the URL never submits an unfinished password change', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  $('editKey').onclick();
  $('managementKey').value = 'unfinished-secret';
  await $('clearURL').onclick();
  const body = JSON.parse(h.requests.find(r => r.method === 'POST').body);
  assert.equal(body.clear_webshare_url, true);
  assert.equal(Object.hasOwn(body, 'management_key'), false);
  assert.equal($('managementKey').value, 'unfinished-secret');
});

test('no bridge or unsupported bridge never grants access and a later ready event can connect', async () => {
  const h = harness(), $ = h.element;
  await h.connect({version:2, request:() => { throw new Error('unsupported bridge called'); }});
  assert.equal(h.requests.length, 0);
  assert.equal($('scan').disabled, true);
  await h.connect();
  assert.equal($('scan').disabled, false);
  await h.connect({version:1});
  assert.equal($('scan').disabled, true);
});

test('initial network failure can retry through the host and never shows raw client errors', async () => {
  const h = harness(), $ = h.element;
  h.reply = async () => { throw new Error('private-key private-url'); };
  await h.connect();
  assert.match($('status').textContent, /网络请求失败/);
  assert.doesNotMatch($('status').textContent, /private/);
  assert.equal($('refresh').disabled, false);
  h.reply = null;
  await $('refresh').onclick();
  assert.equal($('excludes').value, 'saved.json');
  assert.equal($('scan').disabled, false);
});

test('stale POST completion cannot clear drafts from a replacement host', async () => {
  const h = harness(), $ = h.element;
  await h.connect();
  let release;
  h.reply = (path, options) => options.method === 'POST'
    ? new Promise(resolve => { release = resolve; })
    : Promise.resolve({status:200, data:initial()});
  const pending = $('save').onclick();
  await h.detach();
  await h.connect();
  $('url').value = 'new-host-draft'; $('managementKey').value = 'new-host-password';
  release({status:200});
  await pending;
  assert.equal($('url').value, 'new-host-draft');
  assert.equal($('managementKey').value, 'new-host-password');
  assert.equal($('scan').disabled, false);
});

test('malformed state data fails safely and a valid retry restores the UI', async () => {
  const h = harness(), $ = h.element;
  h.reply = async () => ({status:200, data:'private-response'});
  await h.connect();
  assert.equal($('status').textContent, '服务器返回格式无效，请刷新状态。');
  assert.equal($('scan').disabled, true);
  h.reply = null;
  await $('refresh').onclick();
  assert.equal($('scan').disabled, false);
});

for (const format of ['plain', 'v1', 'native-v2', 'manager-plus-v2']) test(`readCPAConnection decodes ${format} without browser writes`, () => {
  for (const prefix of ['', '/prefix']) {
    const location = 'https://cpa.example' + prefix + '/v0/resource/plugins/cpa-plugin-set-proxies/ui';
    const baseURL = 'https://cpa.example' + prefix;
    const raw = auth(baseURL + '/', ' 浏览器-secret ');
    const stored = format === 'plain' ? raw : encodedAuth(raw, format === 'v1' ? 'v1' : 'v2', format === 'manager-plus-v2', location);
    assert.deepEqual(readConnection(stored, location), {base:baseURL, key:'浏览器-secret'});
  }
});

test('readCPAConnection rejects missing, malformed, unsupported and foreign auth scope', () => {
  const invalid = [
    null, '', '{', 'null', '[]', '{}', JSON.stringify({apiBase:'https://cpa.example', managementKey:'legacy-secret'}),
    JSON.stringify({state:{apiBase:'https://cpa.example'}}), auth('https://cpa.example', ''),
    JSON.stringify({state:{apiBase:42, managementKey:'secret'}}),
    JSON.stringify({state:{apiBase:'https://cpa.example', managementKey:42}}),
    'enc::v3::AAAA', 'enc::v2::!!!', 'enc::v1::eA==',
    auth('https://foreign.example'), auth('http://cpa.example'), auth('https://cpa.example:8443'),
    auth('https://cpa.example/other'), auth('https://cpa.example/prefix'),
    auth('https://user:pass@cpa.example'), auth('https://cpa.example?secret=x'), auth('https://cpa.example#secret'),
    auth('https://cpa.example', 'bad\r\nheader'),
  ];
  for (const raw of invalid) assert.equal(readConnection(raw), null, String(raw));
  const prefixed = pageURL.replace('cpa.example/', 'cpa.example/prefix/');
  assert.equal(readConnection(auth(), prefixed), null, 'same origin is insufficient when instance base differs');
  assert.equal(readConnection(auth('https://cpa.example/other'), prefixed), null);
  assert.equal(readConnection(auth(), 'https://cpa.example/unrelated'), null);
  assert.equal(readConnection(encodedAuth(auth(), 'v2', false, pageURL.replace('cpa.example', 'foreign.example'))), null, 'encrypted storage is scoped to host');
});

function storageRequests(h, prefix = '', key = 'browser-secret') {
  for (const request of h.requests.filter(r => r.headers)) {
    assert.ok(new RegExp('^https://cpa\\.example' + prefix + base + '/(state|settings|scan|apply|cancel)$').test(request.path), request.path);
    assert.ok(['GET', 'POST'].includes(request.method));
    assert.equal(request.headers.Authorization, 'Bearer ' + key);
    assert.equal(request.credentials, 'omit');
    assert.equal(request.redirect, 'error');
    assert.equal(request.cache, 'no-store');
    assert.ok(request.signal instanceof AbortSignal, 'requests have a bounded lifetime');
    if (request.method === 'POST') assert.equal(request.headers['Content-Type'], 'application/json');
    else assert.equal(request.body, undefined);
  }
  assert.deepEqual(h.storage.writes, []);
  assert.ok(h.storage.reads.every(key => key === 'cli-proxy-auth'));
}

for (const prefix of ['', '/prefix']) test(`storage-only connection loads and scans current instance ${prefix || '/'}`, async () => {
  const h = harness({storedAuth:auth('https://cpa.example' + prefix), location:pageURL.replace('cpa.example/', 'cpa.example' + prefix + '/')}), $ = h.element;
  await h.ready;
  assert.equal($('scan').disabled, false);
  assert.equal($('excludes').value, 'saved.json');
  assert.equal($('managementKey').value, '', 'browser credential never fills server password input');
  assert.equal(h.requests.filter(r => r.method === 'POST').length, 0, 'connection never persists browser credential on backend');
  h.state.phase = 'scanning';
  await $('scan').onclick();
  const scan = h.requests.find(r => r.path.endsWith('/scan'));
  assert.deepEqual(JSON.parse(scan.body), {});
  assert.equal(h.timers.size, 1);
  assert.equal(h.intervals.size, 1, 'logout watcher is separate from job polling');
  h.state = ready(); await h.tick();
  $('apply').onclick();
  await $('confirmYes').onclick();
  await $('cancel').onclick();
  storageRequests(h, prefix);
  assert.doesNotMatch($('status').textContent + $('summary').textContent, /browser-secret/);
});

test('server management password remains explicit and independent of browser authentication', async () => {
  const h = harness({storedAuth:auth()}), $ = h.element;
  await h.ready;
  h.state.management_key_set = false; await $('refresh').onclick();
  assert.equal($('managementKey').value, '');
  $('editKey').onclick();
  assert.equal($('keyEditor').hidden, false);
  $('managementKey').value = 'server-only-secret';
  await $('saveKey').onclick();
  const post = h.requests.find(r => r.method === 'POST');
  assert.deepEqual(JSON.parse(post.body), {management_key:'server-only-secret'});
  assert.equal(post.headers.Authorization, 'Bearer browser-secret');
  assert.equal($('managementKey').value, '');
  await $('save').onclick();
  assert.equal(Object.hasOwn(JSON.parse(h.requests.filter(r => r.method === 'POST').at(-1).body), 'management_key'), false);
  assert.equal(h.storage.raw, auth());
  storageRequests(h);
});

for (const event of ['storage', 'focus', 'interval']) test(`${event} detects logout, clears sensitive UI and never cancels backend work`, async () => {
  const h = harness({storedAuth:auth()}), $ = h.element;
  await h.ready;
  h.state = {...ready(), phase:'applying', results:[{name:'a.json', status:'success'}]};
  await $('refresh').onclick();
  $('url').value = 'private-url'; $('managementKey').value = 'private-password';
  await h.setAuth(null, false);
  if (event === 'interval') await h.checkAuth();
  else await h.fireEvent(event, {key:'cli-proxy-auth'});
  for (const id of ['url', 'managementKey', 'excludes']) assert.equal($(id).value, '');
  for (const id of ['rows', 'results']) assert.equal($(id).children.length, 0);
  assert.equal($('summary').textContent, '');
  assert.equal($('scan').disabled, true);
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.some(r => r.path.endsWith('/cancel')), false);
  const count = h.requests.length;
  await h.checkAuth();
  assert.equal(h.requests.length, count, 'unchanged logout does not retry');
  await h.setAuth(auth());
  assert.equal($('scan').disabled, true, 'backend is still applying');
  assert.equal(h.timers.size, 1, 'reconnection resumes watching existing backend job');
  storageRequests(h);
});

test('refresh reconnects after login and unrelated storage events do not disturb drafts', async () => {
  const h = harness(), $ = h.element;
  await h.ready;
  await h.setAuth(auth(), false);
  await $('refresh').onclick();
  assert.equal($('scan').disabled, false);
  $('url').value = 'draft';
  const count = h.requests.length;
  await h.fireEvent('storage', {key:'unrelated'});
  await h.fireEvent('focus');
  assert.equal(h.requests.length, count);
  assert.equal($('url').value, 'draft');
  await h.setAuth(null, false);
  await h.fireEvent('storage', {key:null});
  assert.equal($('url').value, '');
  assert.equal($('scan').disabled, true);
  storageRequests(h);
});

for (const method of ['GET', 'POST']) for (const change of ['logout', 'key', 'server']) test(`${method} discards stale response after browser ${change} without relying on events`, async () => {
  const h = harness({storedAuth:auth()}), $ = h.element;
  await h.ready;
  let release;
  h.reply = () => new Promise(resolve => { release = resolve; });
  $('url').value = 'old-session-draft';
  const pending = method === 'GET' ? $('refresh').onclick() : $('save').onclick();
  assert.equal(typeof release, 'function');
  await h.setAuth(change === 'logout' ? null : change === 'key' ? auth('https://cpa.example', 'replacement-key') : auth('https://foreign.example'), false);
  release({status:200, data:{...ready(), phase:'applying'}});
  await pending;
  assert.equal($('scan').disabled, true);
  assert.equal($('rows').children.length, 0);
  assert.equal($('url').value, '');
  assert.equal(h.timers.size, 0);
  assert.equal(h.requests.some(r => r.path.endsWith('/cancel')), false);
  assert.equal(h.requests.filter(r => r.method === 'GET').length, method === 'GET' ? 2 : 1, 'stale POST must not trigger another state read');
  storageRequests(h);
});

test('stale storage POST cannot clear replacement-session drafts or disconnect the new session', async () => {
  const h = harness({storedAuth:auth()}), $ = h.element;
  await h.ready;
  let release;
  h.reply = (path, options) => options.method === 'POST'
    ? new Promise(resolve => { release = resolve; })
    : Promise.resolve({status:200, data:initial()});
  $('url').value = 'old-draft';
  const pending = $('save').onclick();
  await h.setAuth(auth('https://cpa.example', 'replacement-key'));
  $('url').value = 'new-session-draft'; $('managementKey').value = 'new-server-password';
  release({status:200});
  await pending;
  assert.equal($('url').value, 'new-session-draft');
  assert.equal($('managementKey').value, 'new-server-password');
  assert.equal($('scan').disabled, false);
  assert.equal(h.requests.at(-1).headers.Authorization, 'Bearer replacement-key');
  assert.deepEqual(h.storage.writes, []);
});

test('changed browser credential is checked before a new request is sent', async () => {
  const h = harness({storedAuth:auth()});
  await h.ready;
  const before = h.requests.length;
  await h.setAuth(auth('https://cpa.example', 'replacement-key'), false);
  await h.element('scan').onclick();
  assert.equal(h.requests.length, before, 'old adapter cannot send with a newly stored credential');
  assert.equal(h.element('scan').disabled, true);
  await h.fireEvent('focus');
  assert.equal(h.element('scan').disabled, false);
  assert.equal(h.requests.at(-1).headers.Authorization, 'Bearer replacement-key');
  assert.deepEqual(h.storage.writes, []);
});

for (const status of [401, 403]) test(`storage HTTP ${status} disconnects without automatic request loop`, async () => {
  const h = harness({storedAuth:auth()});
  await h.ready;
  h.status = status;
  await h.element('refresh').onclick();
  assert.equal(h.element('scan').disabled, true);
  const count = h.requests.length;
  await h.checkAuth(); await h.checkAuth();
  assert.equal(h.requests.length, count);
  h.status = 200;
  await h.element('refresh').onclick();
  assert.equal(h.element('scan').disabled, false);
  storageRequests(h);
});

test('valid bridge is preferred over storage and does not handle authentication headers', async () => {
  const h = harness({storedAuth:auth()});
  await h.ready;
  h.requests.length = 0;
  await h.connect();
  await h.element('scan').onclick();
  hostRequests(h);
  await h.setAuth(null);
  assert.equal(h.element('scan').disabled, false, 'browser logout must not revoke an independent host bridge');
  assert.deepEqual(h.storage.writes, []);
});

for (const storedAuth of ['corrupt', auth('https://foreign.example'), auth('https://cpa.example/other')]) test(`invalid browser state never sends requests: ${storedAuth}`, async () => {
  const h = harness({storedAuth});
  await h.ready;
  await h.element('refresh').onclick();
  await h.element('scan').onclick();
  assert.equal(h.requests.length, 0);
  assert.equal(h.element('scan').disabled, true);
  assert.equal(h.storage.raw, storedAuth, 'invalid storage must not be cleared');
  assert.deepEqual(h.storage.writes, []);
});

test('outbound CPA authentication errors do not disconnect the panel session', async () => {
  const h = harness(), $ = h.element;
  h.state = {...initial(), phase:'failed', error:'CPA management authentication failed'};
  await h.connect();
  assert.equal($('saveKey').disabled, false);
  assert.equal($('refresh').disabled, false);
  assert.equal($('keyStatus').textContent, '需要更新');
  assert.equal($('settings').open, true);
  assert.equal($('keyEditor').hidden, false);
  assert.match($('status').textContent, /设置中更换/);
});
