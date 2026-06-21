let authToken = localStorage.getItem('xiaolan_cdn_token') || '';
const authHeaders = () => ({'Content-Type':'application/json', 'Authorization': 'Bearer ' + authToken});

const API = {
  async get(url) { const r = await fetch(url, {headers:authHeaders()}); if(r.status===401){doLogout();throw new Error('unauthorized')} return r.json(); },
  async post(url, data) { const r = await fetch(url, {method:'POST',headers:authHeaders(),body:JSON.stringify(data)}); if(r.status===401){doLogout();throw new Error('unauthorized')} return r.json(); },
  async put(url, data) { const r = await fetch(url, {method:'PUT',headers:authHeaders(),body:JSON.stringify(data)}); if(r.status===401){doLogout();throw new Error('unauthorized')} return r.json(); },
  async del(url) { const r = await fetch(url, {method:'DELETE',headers:authHeaders()}); if(r.status===401){doLogout();throw new Error('unauthorized')} return r.json(); }
};

async function doLogin() {
  const u = document.getElementById('login-username').value.trim();
  const p = document.getElementById('login-password').value.trim();
  const errEl = document.getElementById('login-error');
  if (!u || !p) { errEl.textContent = '请输入账号和密码'; errEl.style.display = 'block'; return; }
  try {
    const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
    const d = await r.json();
    if (d.code !== 0) { errEl.textContent = d.message || '登录失败'; errEl.style.display = 'block'; return; }
    authToken = d.data.token;
    localStorage.setItem('xiaolan_cdn_token', authToken);
    document.getElementById('login-overlay').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    document.getElementById('login-error').style.display = 'none';
    loadTab('sites');
  } catch(e) { errEl.textContent = '网络错误'; errEl.style.display = 'block'; }
}

function doLogout() {
  authToken = '';
  localStorage.removeItem('xiaolan_cdn_token');
  document.getElementById('login-overlay').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-username').value = '';
  document.getElementById('login-password').value = '';
}

// Check auth on init
async function checkAuth() {
  if (!authToken) return;
  try {
    const r = await fetch('/api/check-auth', {headers:{'Authorization':'Bearer '+authToken}});
    if (r.status === 200) {
      document.getElementById('login-overlay').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      loadTab('sites');
    } else { doLogout(); }
  } catch(e) { doLogout(); }
}

// Enter key to login
document.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && document.getElementById('login-overlay').style.display !== 'none') {
    doLogin();
  }
});

// Cache
let sitesCache = [], sslCache = [], luaCache = [], nodesCache = [];

// Tab switching
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    loadTab(t.dataset.tab);
  });
});

function loadTab(tab) {
  window.__accessLogsPage = 1;
  window.__systemLogsPage = 1;
  const c = document.getElementById('content');
  switch(tab) {
    case 'sites': renderSites(c); break;
    case 'ssl': renderSSL(c); break;
    case 'lua': renderLua(c); break;
    case 'nodes': renderNodes(c); break;
    case 'logs-access': renderAccessLogs(c); break;
    case 'logs-system': renderSystemLogs(c); break;
  }
}

// ==================== Sites ====================

async function renderSites(container) {
  const res = await API.get('/api/sites');
  sitesCache = res.data || [];
  let h = `<div class="panel"><h2>站点列表 <button class="btn btn-primary btn-sm" onclick="showSiteModal()">+ 新增站点</button></h2>`;
  if (!sitesCache.length) { h += '<div class="empty">暂无站点</div>'; }
  else {
    h += '<table><thead><tr><th>ID</th><th>名称</th><th>源站</th><th>HTTPS</th><th>HTTP/2</th><th>操作</th></tr></thead><tbody>';
    sitesCache.forEach(s => {
      h += `<tr>
        <td>${s.id}</td><td><strong>${esc(s.name)}</strong></td>
        <td>${esc(s.origin_scheme)}://${esc(s.origin_address)}</td>
        <td>${s.https_enabled?'<span class="tag tag-success">开启</span>':'<span class="tag">关闭</span>'}</td>
        <td>${s.http2_enabled?'<span class="tag tag-success">开启</span>':'<span class="tag">关闭</span>'}</td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="showSiteDetail(${s.id})">配置</button>
          <button class="btn btn-danger btn-sm" onclick="deleteSite(${s.id})">删除</button>
        </td></tr>`;
    });
    h += '</tbody></table>';
  }
  h += '</div>';
  container.innerHTML = h;
}

async function showSiteModal(id) {
  let site = {name:'',origin_scheme:'http',origin_address:'',origin_host:'',https_enabled:false,ssl_certificate_id:null,hsts_enabled:false,tls_versions:'TLSv1.2 TLSv1.3',http2_enabled:true,http3_enabled:false,websocket_enabled:false};
  const isEdit = !!id;
  let editDomains = '';
  if (isEdit) {
    const r = await API.get('/api/sites');
    site = (r.data||[]).find(s => s.id === id) || site;
    const dr = await API.get(`/api/site/${id}/domains`);
    editDomains = (dr.data||[]).map(d => d.domain).join('\n');
  }

  if (!sslCache.length) { const r = await API.get('/api/ssl'); sslCache = r.data||[]; }

  let sslOpts = '<option value="">不使用证书</option>';
  sslCache.forEach(c => { sslOpts += `<option value="${c.id}" ${site.ssl_certificate_id===c.id?'selected':''}>${esc(c.name)}</option>`; });

  const tlsEnabled = site.https_enabled && site.ssl_certificate_id;
  const tlsDis = tlsEnabled ? '' : ' disabled';
  const tls = tlsToChecked(site.tls_versions);

  const html = `
    <div class="modal active" onclick="if(event.target===this)this.remove()">
      <div class="modal-content">
        <h3>${isEdit?'编辑站点':'新增站点'}</h3>
        <div class="form-row">
          <div class="form-group"><label>站点名称</label><input id="site-name" value="${esc(site.name)}"></div>
          <div class="form-group"><label>域名 (每行一个)</label><textarea id="site-domains" rows="3" placeholder="每行输入一个域名">${esc(editDomains)}</textarea></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>回源Host</label><input id="site-origin-host" value="${esc(site.origin_host||'')}" placeholder="留空则不修改Host"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>源站协议</label><select id="site-origin-scheme"><option value="http" ${site.origin_scheme==='http'?'selected':''}>HTTP</option><option value="https" ${site.origin_scheme==='https'?'selected':''}>HTTPS</option></select></div>
          <div class="form-group"><label>源站地址</label><input id="site-origin-addr" value="${esc(site.origin_address)}" placeholder="例如: 1.1.1.1:443"></div>
        </div>
        <div class="form-row">
          <div class="checkbox-group" style="align-self:center"><input type="checkbox" id="site-https" ${site.https_enabled?'checked':''} onchange="toggleHttpsDeps('site-')"><label>HTTPS</label></div>
          <div class="form-group" style="flex:1"><select id="site-ssl-id" onchange="toggleHttpsDeps('site-')">${sslOpts}</select></div>
          <div class="checkbox-group" style="align-self:center"><input type="checkbox" id="site-hsts" ${site.hsts_enabled?'checked':''}${tlsDis}><label>HSTS</label></div>
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label>TLS版本</label>
            <div style="display:flex;gap:12px;flex-wrap:wrap">
              <div class="checkbox-group"><input type="checkbox" id="site-tls-1.2" value="TLSv1.2" ${tls['TLSv1.2']?'checked':''}${tlsDis}><label>TLS 1.2</label></div>
              <div class="checkbox-group"><input type="checkbox" id="site-tls-1.3" value="TLSv1.3" ${tls['TLSv1.3']?'checked':''}${tlsDis}><label>TLS 1.3</label></div>
            </div>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label>协议</label>
            <div style="display:flex;gap:16px">
              <div class="checkbox-group"><input type="checkbox" id="site-http2" ${site.http2_enabled?'checked':''}${tlsDis}><label>HTTP/2</label></div>
              <div class="checkbox-group"><input type="checkbox" id="site-http3" ${site.http3_enabled?'checked':''}${tlsDis}><label>HTTP/3</label></div>
              <div class="checkbox-group"><input type="checkbox" id="site-websocket" ${site.websocket_enabled?'checked':''}><label>WebSocket</label></div>
            </div>
          </div>
        </div>
        <div class="modal-actions">
          <button class="btn btn-outline" onclick="closeModal()">取消</button>
          <button class="btn btn-primary" onclick="saveSite(${isEdit?id:0},${isEdit})">保存</button>
        </div>
      </div>
    </div>`;
  showModalHTML(html);
}

async function saveSite(id, isEdit) {
  const tlsVersions = [];
  ['1.2','1.3'].forEach(v => {
    if (gc('site-tls-'+v)) tlsVersions.push('TLSv'+v);
  });
  if (!tlsVersions.length) tlsVersions.push('TLSv1.2','TLSv1.3');

  const data = {
    name: gv('site-name'), origin_scheme: gv('site-origin-scheme'), origin_address: gv('site-origin-addr'),
    origin_host: gv('site-origin-host'), https_enabled: gc('site-https'), ssl_certificate_id: gv('site-ssl-id') ? parseInt(gv('site-ssl-id')) : null,
    hsts_enabled: gc('site-hsts'), tls_versions: tlsVersions.join(' '), http2_enabled: gc('site-http2'), http3_enabled: gc('site-http3'), websocket_enabled: gc('site-websocket')
  };
  if (!data.name || !data.origin_address) { alert('请填写站点名称和源站地址'); return; }
  if (data.https_enabled && !data.ssl_certificate_id) { alert('开启HTTPS必须选择SSL证书'); return; }

  let siteId = id;
  if (id) { data.id = id; await API.put('/api/sites', data); }
  else {
    const r = await API.post('/api/sites', data);
    siteId = r.data ? r.data.id : 0;
  }

  // Save domains
  const domainText = gv('site-domains').trim();
  if (domainText && siteId) {
    const newDomains = domainText.split('\n').map(s => s.trim()).filter(Boolean);
    for (const d of newDomains) {
      try { await API.post(`/api/site/${siteId}/domains`, {domain:d}); } catch(e) {}
    }
  }

  closeModal(); renderSites(document.getElementById('content'));
}

async function deleteSite(id) { if (confirm('确认删除此站点？')) { await API.del('/api/site/'+id); renderSites(document.getElementById('content')); } }

async function saveSiteSettings(siteId) {
  const tlsVersions = [];
  ['1.2','1.3'].forEach(v => {
    if (gc('detail-site-tls-'+v)) tlsVersions.push('TLSv'+v);
  });
  if (!tlsVersions.length) tlsVersions.push('TLSv1.2','TLSv1.3');

  const data = {
    id: siteId,
    name: gv('detail-site-name'), origin_scheme: gv('detail-site-origin-scheme'), origin_address: gv('detail-site-origin-addr'),
    origin_host: gv('detail-site-origin-host'), https_enabled: gc('detail-site-https'),
    ssl_certificate_id: gv('detail-site-ssl-id') ? parseInt(gv('detail-site-ssl-id')) : null,
    hsts_enabled: gc('detail-site-hsts'), tls_versions: tlsVersions.join(' '),
    http2_enabled: gc('detail-site-http2'), http3_enabled: gc('detail-site-http3'), websocket_enabled: gc('detail-site-websocket')
  };
  if (!data.name || !data.origin_address) { alert('请填写站点名称和源站地址'); return; }
  if (data.https_enabled && !data.ssl_certificate_id) { alert('开启HTTPS必须选择SSL证书'); return; }
  await API.put('/api/sites', data);
  // Refresh cache
  const r = await API.get('/api/sites');
  sitesCache = r.data || [];
  alert('保存成功');
}

// ==================== Site Detail (domains, redirects, cache, path origins, lua, blacklist, traffic) ====================

async function showSiteDetail(siteId) {
  const site = sitesCache.find(s => s.id === siteId);
  if (!site) return;

  const [domains, redirects, cache, pathOrigin, luaBindings, blacklist] = await Promise.all([
    API.get(`/api/site/${siteId}/domains`),
    API.get(`/api/site/${siteId}/redirects`),
    API.get(`/api/site/${siteId}/cache`),
    API.get(`/api/site/${siteId}/pathorigin`),
    API.get(`/api/site/${siteId}/lua`),
    API.get(`/api/site/${siteId}/blacklist`),
  ]);

  if (!luaCache.length) { const r = await API.get('/api/lua'); luaCache = r.data||[]; }
  if (!sslCache.length) { const r = await API.get('/api/ssl'); sslCache = r.data||[]; }

  let sslOpts = '<option value="">不使用证书</option>';
  sslCache.forEach(c => { sslOpts += `<option value="${c.id}" ${site.ssl_certificate_id===c.id?'selected':''}>${esc(c.name)}</option>`; });

  const tlsEnabled = site.https_enabled && site.ssl_certificate_id;
  const dtlsDis = tlsEnabled ? '' : ' disabled';
  const tls = tlsToChecked(site.tls_versions);

  let h = `<div class="panel"><h2>${esc(site.name)} 配置 <button class="btn btn-outline btn-sm" onclick="renderSites(document.getElementById('content'))">← 返回</button></h2>`;

  // === Site basic settings ===
  h += `<div class="section"><h4>站点基本设置</h4>`;
  h += `<div class="form-row">
    <div class="form-group"><label>站点名称</label><input id="detail-site-name" value="${esc(site.name)}"></div>
    <div class="form-group"><label>回源Host</label><input id="detail-site-origin-host" value="${esc(site.origin_host||'')}" placeholder="留空不修改Host"></div>
  </div>`;
  h += `<div class="form-row">
    <div class="form-group"><label>源站协议</label><select id="detail-site-origin-scheme"><option value="http" ${site.origin_scheme==='http'?'selected':''}>HTTP</option><option value="https" ${site.origin_scheme==='https'?'selected':''}>HTTPS</option></select></div>
    <div class="form-group"><label>源站地址</label><input id="detail-site-origin-addr" value="${esc(site.origin_address)}"></div>
  </div>`;
  h += `<div class="form-row" style="align-items:center">
    <div class="checkbox-group"><input type="checkbox" id="detail-site-https" ${site.https_enabled?'checked':''} onchange="toggleHttpsDeps('detail-site-')"><label>HTTPS</label></div>
    <div class="form-group" style="flex:1"><select id="detail-site-ssl-id" onchange="toggleHttpsDeps('detail-site-')">${sslOpts}</select></div>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-hsts" ${site.hsts_enabled?'checked':''}${dtlsDis}><label>HSTS</label></div>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-http2" ${site.http2_enabled?'checked':''}${dtlsDis}><label>HTTP/2</label></div>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-http3" ${site.http3_enabled?'checked':''}${dtlsDis}><label>HTTP/3</label></div>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-websocket" ${site.websocket_enabled?'checked':''}><label>WebSocket</label></div>
  </div>`;
  h += `<div class="form-row" style="align-items:center">
    <label style="font-size:13px;font-weight:500;color:#555;white-space:nowrap">TLS版本</label>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-tls-1.2" value="TLSv1.2" ${tls['TLSv1.2']?'checked':''}${dtlsDis}><label>TLS 1.2</label></div>
    <div class="checkbox-group"><input type="checkbox" id="detail-site-tls-1.3" value="TLSv1.3" ${tls['TLSv1.3']?'checked':''}${dtlsDis}><label>TLS 1.3</label></div>
  </div>`;
  h += `<button class="btn btn-primary btn-sm" onclick="saveSiteSettings(${siteId})" style="margin-top:8px">保存基本设置</button></div>`;

  // === Domains section ===
  h += `<div class="section"><h4>域名管理</h4>`;
  h += `<div class="inline-form"><input id="new-domain" placeholder="输入域名"><button class="btn btn-primary btn-sm" onclick="addDomain(${siteId})">添加</button></div>`;
  h += '<div class="inline-list">';
  (domains.data||[]).forEach(d => {
    h += `<div class="inline-item"><span>${esc(d.domain)}</span><button class="btn btn-danger btn-sm" onclick="delDomain(${siteId},${d.id})">删除</button></div>`;
  });
  h += '</div></div>';

  // === Redirect rules ===
  h += `<div class="section"><h4>域名重定向</h4>`;
  h += `<div class="inline-form">
    <select id="new-redirect-type"><option value="301">301</option><option value="302">302</option></select>
    <input id="new-redirect-from" placeholder="来源域名 (如 old.x.com)" style="width:220px">
    <input id="new-redirect-to" placeholder="目标URL (如 http://new.x.com)" style="width:280px">
    <button class="btn btn-primary btn-sm" onclick="addRedirect(${siteId})">添加</button></div>`;
  (redirects.data||[]).forEach(r => {
    h += `<div class="inline-item"><span>${r.redirect_type} | ${esc(r.from_path)} → ${esc(r.to_url)}</span><button class="btn btn-danger btn-sm" onclick="delRedirect(${siteId},${r.id})">删除</button></div>`;
  });
  h += '</div>';

  // === Cache rules ===
  h += `<div class="section"><h4>缓存规则</h4>`;
  h += `<div class="inline-form">
    <input id="new-cache-suffix" placeholder="后缀名，逗号分隔 (如 jpg,png,css)" style="width:260px">
    <input id="new-cache-time" placeholder="缓存时间 (如 30d)" style="width:140px">
    <button class="btn btn-primary btn-sm" onclick="addCache(${siteId})">批量添加</button></div>`;
  (cache.data||[]).forEach(c => {
    h += `<div class="inline-item"><span>.${esc(c.suffix)} → ${esc(c.cache_time)}</span><button class="btn btn-danger btn-sm" onclick="delCache(${siteId},${c.id})">删除</button></div>`;
  });
  h += '</div>';

  // === Path origin rules ===
  h += `<div class="section"><h4>分路径回源规则 (支持正则)</h4>`;
  h += `<div class="inline-form">
    <select id="new-po-scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select>
    <input id="new-po-pattern" placeholder="路径正则 (如 ^/api/)" style="width:180px">
    <input id="new-po-addr" placeholder="回源地址" style="width:180px">
    <input id="new-po-host" placeholder="回源Host" style="width:160px">
    <button class="btn btn-primary btn-sm" onclick="addPathOrigin(${siteId})">添加</button></div>`;
  (pathOrigin.data||[]).forEach(p => {
    h += `<div class="inline-item"><span>${esc(p.origin_scheme)}://${esc(p.origin_address)} | ${esc(p.path_pattern)} | Host:${esc(p.origin_host||'默认')}</span><button class="btn btn-danger btn-sm" onclick="delPathOrigin(${siteId},${p.id})">删除</button></div>`;
  });
  h += '</div>';

  // === Lua binding ===
  const currentLua = luaBindings.data;
  const currentLuaId = currentLua ? currentLua.lua_script_id : 0;
  h += `<div class="section"><h4>Lua脚本绑定</h4>`;
  let luaOpts = `<option value="">不使用</option>` + luaCache.map(l => `<option value="${l.id}" ${l.id===currentLuaId?'selected':''}>${esc(l.name)}</option>`).join('');
  h += `<div class="inline-form">
    <select id="new-lua-binding">${luaOpts}</select>
    <button class="btn btn-primary btn-sm" onclick="addLuaBinding(${siteId})">保存</button>
    <button class="btn btn-outline btn-sm" onclick="delLuaBinding(${siteId})">解绑</button></div>`;
  if (currentLua) {
    h += `<div style="font-size:12px;color:#999;margin-top:4px">当前绑定: ${esc(currentLua.script_name)}</div>`;
  }
  h += '</div>';

  // === IP Blacklist ===
  h += `<div class="section"><h4>IP黑名单</h4>`;
  h += `<div class="inline-form"><input id="new-blacklist-ip" placeholder="IP地址"><button class="btn btn-primary btn-sm" onclick="addBlacklist(${siteId})">添加</button></div>`;
  (blacklist.data||[]).forEach(ip => {
    h += `<div class="inline-item"><span>${esc(ip.ip_address)}</span><button class="btn btn-danger btn-sm" onclick="delBlacklist(${siteId},${ip.id})">删除</button></div>`;
  });
  h += '</div>';

  // === Traffic ===
  h += `<div class="section"><h4>域名流量
    <span style="font-weight:normal;font-size:12px;margin-left:10px">
      <a href="javascript:void(0)" onclick="loadTraffic(${siteId},'24h')" id="traffic-24h" style="color:#0f3460;font-weight:600">近24小时</a> |
      <a href="javascript:void(0)" onclick="loadTraffic(${siteId},'7d')" id="traffic-7d">近7天</a> |
      <a href="javascript:void(0)" onclick="loadTraffic(${siteId},'30d')" id="traffic-30d">近30天</a> |
      <a href="javascript:void(0)" onclick="loadTraffic(${siteId},'all')" id="traffic-all">累计</a>
    </span></h4>
    <div id="traffic-data">加载中...</div></div>`;

  // === Cache purge ===
  h += `<div class="section"><h4>缓存刷新</h4>
    <div class="inline-form">
      <input id="purge-path" placeholder="刷新路径 (留空刷新全站)" style="width:250px">
      <button class="btn btn-danger btn-sm" onclick="purgeCache(${siteId})">执行刷新</button>
    </div></div>`;

  h += '</div>';
  document.getElementById('content').innerHTML = h;
  loadTraffic(siteId, '24h');
}

async function loadTraffic(siteId, range) {
  const container = document.getElementById('traffic-data');
  if (!container) return;
  ['24h','7d','30d','all'].forEach(r => {
    const el = document.getElementById('traffic-'+r);
    if (el) el.style.cssText = r === range ? 'color:#0f3460;font-weight:600' : '';
  });
  container.innerHTML = '加载中...';
  const r = await API.get(`/api/site/${siteId}/traffic?range=${range}`);
  const data = (r.data||[]);
  if (!data.length) { container.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  let h = '<table><thead><tr><th>域名</th><th>请求数</th><th>总流量</th></tr></thead><tbody>';
  data.forEach(t => {
    h += `<tr><td>${esc(t.domain)}</td><td>${t.request_count}</td><td>${formatBytes(t.total_bytes)}</td></tr>`;
  });
  h += '</tbody></table>';
  container.innerHTML = h;
}

// Sub-resource CRUD
async function addDomain(siteId) {
  const v = document.getElementById('new-domain').value.trim();
  if (!v) return;
  await API.post(`/api/site/${siteId}/domains`, {domain:v});
  showSiteDetail(siteId);
}
async function delDomain(siteId, id) { await API.del(`/api/site/${siteId}/domains/${id}`); showSiteDetail(siteId); }
async function addRedirect(siteId) {
  const from = document.getElementById('new-redirect-from').value.trim();
  const to = document.getElementById('new-redirect-to').value.trim();
  const type = parseInt(document.getElementById('new-redirect-type').value);
  if (!from || !to) return;
  await API.post(`/api/site/${siteId}/redirects`, {from_path:from, to_url:to, redirect_type:type});
  showSiteDetail(siteId);
}
async function delRedirect(siteId, id) { await API.del(`/api/site/${siteId}/redirects/${id}`); showSiteDetail(siteId); }
async function addCache(siteId) {
  const suffixStr = gv('new-cache-suffix');
  const time = gv('new-cache-time') || '30d';
  const suffixes = suffixStr.split(/[,，\s]+/).map(s => s.trim().replace(/^\./, '')).filter(Boolean);
  if (!suffixes.length) return;
  for (const suffix of suffixes) {
    try { await API.post(`/api/site/${siteId}/cache`, {suffix, cache_time:time}); } catch(e) {}
  }
  showSiteDetail(siteId);
}
async function delCache(siteId, id) { await API.del(`/api/site/${siteId}/cache/${id}`); showSiteDetail(siteId); }
async function addPathOrigin(siteId) {
  const scheme = document.getElementById('new-po-scheme').value;
  const pattern = document.getElementById('new-po-pattern').value.trim();
  const addr = document.getElementById('new-po-addr').value.trim();
  const host = document.getElementById('new-po-host').value.trim();
  if (!pattern || !addr) return;
  await API.post(`/api/site/${siteId}/pathorigin`, {path_pattern:pattern, origin_scheme:scheme, origin_address:addr, origin_host:host});
  showSiteDetail(siteId);
}
async function delPathOrigin(siteId, id) { await API.del(`/api/site/${siteId}/pathorigin/${id}`); showSiteDetail(siteId); }
async function addLuaBinding(siteId) {
  const luaId = parseInt(gv('new-lua-binding')) || 0;
  await API.post(`/api/site/${siteId}/lua`, {lua_script_id:luaId});
  showSiteDetail(siteId);
}
async function delLuaBinding(siteId) { await API.del(`/api/site/${siteId}/lua`); showSiteDetail(siteId); }
async function addBlacklist(siteId) {
  const ip = document.getElementById('new-blacklist-ip').value.trim();
  if (!ip) return;
  await API.post(`/api/site/${siteId}/blacklist`, {ip_address:ip});
  showSiteDetail(siteId);
}
async function delBlacklist(siteId, id) { await API.del(`/api/site/${siteId}/blacklist/${id}`); showSiteDetail(siteId); }
async function purgeCache(siteId) {
  const path = document.getElementById('purge-path').value.trim();
  const r = await API.post('/api/action/purge', {site_id:siteId, path});
  alert(r.message);
}

// ==================== SSL Certificates ====================

async function renderSSL(container) {
  const res = await API.get('/api/ssl');
  sslCache = res.data || [];
  let h = `<div class="panel"><h2>SSL证书管理 <button class="btn btn-primary btn-sm" onclick="showSSLModal()">+ 新增证书</button></h2>`;
  if (!sslCache.length) { h += '<div class="empty">暂无证书</div>'; }
  else {
    h += '<table><thead><tr><th>ID</th><th>名称</th><th>公钥</th><th>私钥</th><th>更新时间</th><th>操作</th></tr></thead><tbody>';
    sslCache.forEach(c => {
      h += `<tr><td>${c.id}</td><td>${esc(c.name)}</td>
        <td><code>${esc(c.public_key.substring(0,40))}...</code></td>
        <td><code>${esc(c.private_key.substring(0,40))}...</code></td>
        <td>${c.updated_at}</td>
        <td><button class="btn btn-outline btn-sm" onclick="showSSLModal(${c.id})">编辑</button>
        <button class="btn btn-danger btn-sm" onclick="deleteSSL(${c.id})">删除</button></td></tr>`;
    });
    h += '</tbody></table>';
  }
  h += '</div>'; container.innerHTML = h;
}

function showSSLModal(id) {
  let cert = {name:'',public_key:'',private_key:''};
  if (id) cert = sslCache.find(c => c.id === id) || cert;
  const html = `<div class="modal active" onclick="if(event.target===this)this.remove()">
    <div class="modal-content"><h3>${id?'编辑':'新增'}证书</h3>
      <div class="form-group"><label>名称 (唯一)</label><input id="ssl-name" value="${esc(cert.name)}"></div>
      <div class="form-group"><label>公钥 (pem格式)</label><textarea id="ssl-pub" rows="6">${esc(cert.public_key)}</textarea></div>
      <div class="form-group"><label>私钥 (key格式)</label><textarea id="ssl-priv" rows="6">${esc(cert.private_key)}</textarea></div>
      <div class="modal-actions"><button class="btn btn-outline" onclick="closeModal()">取消</button>
      <button class="btn btn-primary" onclick="saveSSL(${id||0})">保存</button></div>
    </div></div>`;
  showModalHTML(html);
}

async function saveSSL(id) {
  const data = {name:gv('ssl-name'),public_key:gv('ssl-pub'),private_key:gv('ssl-priv')};
  if (!data.name||!data.public_key||!data.private_key) { alert('所有字段必填'); return; }
  if (id) { data.id = id; await API.put('/api/ssl', data); }
  else { await API.post('/api/ssl', data); }
  closeModal(); renderSSL(document.getElementById('content'));
}
async function deleteSSL(id) { if (confirm('确认删除？')) { await API.del('/api/ssl/'+id); renderSSL(document.getElementById('content')); } }

// ==================== Lua Scripts ====================

async function renderLua(container) {
  const res = await API.get('/api/lua');
  luaCache = res.data || [];
  let h = `<div class="panel"><h2>Lua脚本管理 <button class="btn btn-primary btn-sm" onclick="showLuaModal()">+ 新增脚本</button></h2>`;
  if (!luaCache.length) { h += '<div class="empty">暂无脚本</div>'; }
  else {
    h += '<table><thead><tr><th>ID</th><th>名称</th><th>内容</th><th>操作</th></tr></thead><tbody>';
    luaCache.forEach(l => {
      h += `<tr><td>${l.id}</td><td>${esc(l.name)}</td>
        <td><pre style="max-height:60px;overflow:auto;font-size:11px">${esc(l.content.substring(0,100))}</pre></td>
        <td><button class="btn btn-outline btn-sm" onclick="showLuaModal(${l.id})">编辑</button>
        <button class="btn btn-danger btn-sm" onclick="deleteLua(${l.id})">删除</button></td></tr>`;
    });
    h += '</tbody></table>';
  }
  h += '</div>'; container.innerHTML = h;
}

function showLuaModal(id) {
  let script = {name:'',content:''};
  if (id) script = luaCache.find(l => l.id === id) || script;
  const html = `<div class="modal active" onclick="if(event.target===this)this.remove()">
    <div class="modal-content"><h3>${id?'编辑':'新增'}脚本</h3>
      <div class="form-group"><label>名称 (唯一)</label><input id="lua-name" value="${esc(script.name)}"></div>
      <div class="form-group"><label>脚本内容</label><textarea id="lua-content" rows="10">${esc(script.content)}</textarea></div>
      <div class="modal-actions"><button class="btn btn-outline" onclick="closeModal()">取消</button>
      <button class="btn btn-primary" onclick="saveLua(${id||0})">保存</button></div>
    </div></div>`;
  showModalHTML(html);
}

async function saveLua(id) {
  const data = {name:gv('lua-name'),content:gv('lua-content')};
  if (!data.name||!data.content) { alert('所有字段必填'); return; }
  if (id) { data.id = id; await API.put('/api/lua', data); }
  else { await API.post('/api/lua', data); }
  closeModal(); renderLua(document.getElementById('content'));
}
async function deleteLua(id) { if (confirm('确认删除？')) { await API.del('/api/lua/'+id); renderLua(document.getElementById('content')); } }

// ==================== Nodes ====================

async function renderNodes(container) {
  const res = await API.get('/api/nodes');
  nodesCache = res.data || [];
  let h = `<div class="panel"><h2>节点管理 <button class="btn btn-primary btn-sm" onclick="showNodeModal()">+ 新增节点</button></h2>`;
  if (!nodesCache.length) { h += '<div class="empty">暂无节点</div>'; }
  else {
    h += '<table><thead><tr><th>ID</th><th>名称</th><th>主机</th><th>端口</th><th>用户名</th><th>操作</th></tr></thead><tbody>';
    nodesCache.forEach(n => {
      h += `<tr><td>${n.id}</td><td>${esc(n.name)}</td><td>${esc(n.host)}</td><td>${n.port}</td><td>${esc(n.username)}</td>
        <td><button class="btn btn-outline btn-sm" onclick="showNodeModal(${n.id})">编辑</button>
        <button class="btn btn-danger btn-sm" onclick="deleteNode(${n.id})">删除</button></td></tr>`;
    });
    h += '</tbody></table>';
  }
  h += '</div>'; container.innerHTML = h;
}

function showNodeModal(id) {
  let node = {name:'',host:'',port:22,username:'root',password:''};
  if (id) node = nodesCache.find(n => n.id === id) || node;
  const html = `<div class="modal active" onclick="if(event.target===this)this.remove()">
    <div class="modal-content"><h3>${id?'编辑':'新增'}节点</h3>
      <div class="form-row"><div class="form-group"><label>名称</label><input id="node-name" value="${esc(node.name)}"></div>
      <div class="form-group"><label>主机</label><input id="node-host" value="${esc(node.host)}"></div></div>
      <div class="form-row"><div class="form-group"><label>端口</label><input id="node-port" type="number" value="${node.port}"></div>
      <div class="form-group"><label>用户名</label><input id="node-user" value="${esc(node.username)}"></div></div>
      <div class="form-group"><label>密码 (明文存储)</label><input id="node-pass" type="text" value="${esc(node.password)}"></div>
      <div class="modal-actions"><button class="btn btn-outline" onclick="closeModal()">取消</button>
      <button class="btn btn-primary" onclick="saveNode(${id||0})">保存</button></div>
    </div></div>`;
  showModalHTML(html);
}

async function saveNode(id) {
  const data = {name:gv('node-name'),host:gv('node-host'),port:parseInt(gv('node-port'))||22,username:gv('node-user')||'root',password:gv('node-pass')};
  if (!data.name||!data.host||!data.password) { alert('名称、主机、密码必填'); return; }
  if (id) { data.id = id; await API.put('/api/nodes', data); }
  else { await API.post('/api/nodes', data); }
  closeModal(); renderNodes(document.getElementById('content'));
}
async function deleteNode(id) { if (confirm('确认删除？')) { await API.del('/api/node/'+id); renderNodes(document.getElementById('content')); } }

// ==================== Logs ====================

async function renderAccessLogs(container) {
  const domain = document.getElementById('log-filter-domain')?.value || '';
  const code = document.getElementById('log-filter-code')?.value || '';
  const start = document.getElementById('log-filter-start')?.value || '';
  const end = document.getElementById('log-filter-end')?.value || '';
  const page = window.__accessLogsPage || 1;
  const pageSize = 20;
  let url = `/api/logs/access?page=${page}&page_size=${pageSize}`;
  if (domain) url += '&domain=' + encodeURIComponent(domain);
  if (code) url += '&status_code=' + code;
  if (start) url += '&start_time=' + start;
  if (end) url += '&end_time=' + end;
  const res = await API.get(url);
  const data = res.data || {};
  const logs = data.data || [];
  const total = data.total || 0;

  let h = `<div class="panel"><h2>访问日志
    <span style="font-weight:normal;font-size:12px;margin-left:12px">
      <select id="access-delete-before" style="width:100px;padding:3px">
        <option value="1">近一天</option><option value="3">近三天</option><option value="7">近七天</option>
        <option value="14">近十四天</option><option value="30">近三十天</option><option value="all">全部</option>
      </select>
      <button class="btn btn-danger btn-sm" onclick="deleteLogs('access')">删除日志</button>
    </span></h2>
    <div class="filter-bar">
      <div class="form-group"><label>域名</label><input id="log-filter-domain" value="${esc(domain)}" placeholder="域名筛选"></div>
      <div class="form-group"><label>状态码</label><input id="log-filter-code" value="${esc(code)}" placeholder="如 200"></div>
      <div class="form-group"><label>开始时间</label><input id="log-filter-start" type="datetime-local" value="${start}"></div>
      <div class="form-group"><label>结束时间</label><input id="log-filter-end" type="datetime-local" value="${end}"></div>
      <button class="btn btn-primary btn-sm" onclick="window.__accessLogsPage=1;renderAccessLogs(document.getElementById('content'))">查询</button>
    </div>`;

  if (!logs.length) { h += '<div class="empty">暂无日志</div>'; }
  else {
    h += `<table><thead><tr><th>时间</th><th>域名</th><th>路径</th><th>状态</th><th>IP</th><th>UA</th><th>字节</th></tr></thead><tbody>`;
    logs.forEach(l => {
      h += `<tr><td style="white-space:nowrap">${l.request_time}</td><td>${esc(l.domain)}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(l.request_path)}</td>
        <td>${statusTag(l.status_code)}</td><td>${esc(l.client_ip)}</td>
        <td style="max-width:200px">${uaExpand(l.user_agent||'')}</td>
        <td>${formatBytes(l.bytes_sent)}</td></tr>`;
    });
    h += '</tbody></table>';
    if (total > pageSize) {
      const totalPages = Math.ceil(total / pageSize);
      h += `<div class="pagination">
        <button class="btn btn-outline btn-sm" onclick="window.__accessLogsPage=${Math.max(1,page-1)};renderAccessLogs(document.getElementById('content'))" ${page<=1?'disabled':''}>上一页</button>
        <span>第 ${page} / ${totalPages} 页 (共 ${total} 条)</span>
        <button class="btn btn-outline btn-sm" onclick="window.__accessLogsPage=${Math.min(totalPages,page+1)};renderAccessLogs(document.getElementById('content'))" ${page>=totalPages?'disabled':''}>下一页</button></div>`;
    }
  }
  h += '</div>';
  container.innerHTML = h;
}

async function renderSystemLogs(container) {
  const level = document.getElementById('syslog-level')?.value || '';
  const category = document.getElementById('syslog-cat')?.value || '';
  const page = window.__systemLogsPage || 1;
  const pageSize = 20;
  let url = `/api/logs/system?page=${page}&page_size=${pageSize}`;
  if (level) url += '&level=' + level;
  if (category) url += '&category=' + category;
  const res = await API.get(url);
  const data = res.data || {};
  const logs = data.data || [];
  const total = data.total || 0;

  let h = `<div class="panel"><h2>系统日志
    <span style="font-weight:normal;font-size:12px;margin-left:12px">
      <select id="system-delete-before" style="width:100px;padding:3px">
        <option value="1">近一天</option><option value="3">近三天</option><option value="7">近七天</option>
        <option value="14">近十四天</option><option value="30">近三十天</option><option value="all">全部</option>
      </select>
      <button class="btn btn-danger btn-sm" onclick="deleteLogs('system')">删除日志</button>
    </span></h2>
    <div class="filter-bar">
      <div class="form-group"><label>级别</label><select id="syslog-level"><option value="">全部</option><option value="INFO" ${level==='INFO'?'selected':''}>INFO</option><option value="WARN" ${level==='WARN'?'selected':''}>WARN</option><option value="ERROR" ${level==='ERROR'?'selected':''}>ERROR</option></select></div>
      <div class="form-group"><label>分类</label><select id="syslog-cat"><option value="">全部</option><option value="sync" ${category==='sync'?'selected':''}>同步</option><option value="log_collect" ${category==='log_collect'?'selected':''}>日志采集</option><option value="site" ${category==='site'?'selected':''}>站点</option><option value="ssl" ${category==='ssl'?'selected':''}>证书</option><option value="lua" ${category==='lua'?'selected':''}>脚本</option><option value="node" ${category==='node'?'selected':''}>节点</option><option value="system" ${category==='system'?'selected':''}>系统</option></select></div>
      <button class="btn btn-primary btn-sm" onclick="window.__systemLogsPage=1;renderSystemLogs(document.getElementById('content'))">查询</button>
    </div>`;

  if (!logs.length) { h += '<div class="empty">暂无日志</div>'; }
  else {
    h += '<table><thead><tr><th>时间</th><th>级别</th><th>分类</th><th>消息</th><th>详情</th></tr></thead><tbody>';
    logs.forEach(l => {
      const lvlTag = l.level === 'ERROR' ? '<span class="tag tag-danger">ERROR</span>' :
                     l.level === 'WARN' ? '<span class="tag" style="background:#fff3cd">WARN</span>' : '<span class="tag">INFO</span>';
      h += `<tr><td style="white-space:nowrap">${l.created_at}</td><td>${lvlTag}</td><td>${esc(l.category)}</td>
        <td>${esc(l.message)}</td><td class="log-detail">${esc(l.detail||'')}</td></tr>`;
    });
    h += '</tbody></table>';
    if (total > pageSize) {
      const totalPages = Math.ceil(total / pageSize);
      h += `<div class="pagination">
        <button class="btn btn-outline btn-sm" onclick="window.__systemLogsPage=${Math.max(1,page-1)};renderSystemLogs(document.getElementById('content'))" ${page<=1?'disabled':''}>上一页</button>
        <span>第 ${page} / ${totalPages} 页 (共 ${total} 条)</span>
        <button class="btn btn-outline btn-sm" onclick="window.__systemLogsPage=${Math.min(totalPages,page+1)};renderSystemLogs(document.getElementById('content'))" ${page>=totalPages?'disabled':''}>下一页</button></div>`;
    }
  }
  h += '</div>';
  container.innerHTML = h;
}

// ==================== Actions ====================

async function forceSync() {
  const s = document.getElementById('sync-status');
  s.textContent = '同步中...';
  const r = await API.post('/api/action/sync');
  s.textContent = r.message || '已触发同步';
  setTimeout(() => s.textContent = '', 3000);
}

// ==================== Helpers ====================

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function gv(id) { const e = document.getElementById(id); return e ? e.value : ''; }
function gc(id) { const e = document.getElementById(id); return e ? e.checked : false; }
function showModalHTML(html) { const d = document.createElement('div'); d.innerHTML = html; document.body.appendChild(d.firstElementChild); }
function closeModal() { const m = document.querySelector('.modal'); if (m) m.remove(); }
function statusTag(code) { if (code >= 200 && code < 300) return `<span class="tag tag-success">${code}</span>`; if (code >= 400 && code < 500) return `<span class="tag" style="background:#fff3cd">${code}</span>`; if (code >= 500) return `<span class="tag tag-danger">${code}</span>`; return `<span class="tag">${code}</span>`; }
async function deleteLogs(type) {
  const el = document.getElementById(type + '-delete-before');
  const before = el ? el.value : '1';
  if (before === 'all' && !confirm('确认删除全部日志？此操作不可恢复！')) return;
  const r = await API.del(`/api/logs/${type}?before=${before}`);
  alert(r.message);
  if (type === 'access') renderAccessLogs(document.getElementById('content'));
  else renderSystemLogs(document.getElementById('content'));
}

function uaExpand(ua) {
  const max = 50;
  if (!ua || ua.length <= max) return esc(ua);
  const id = 'ua-' + Math.random().toString(36).slice(2,8);
  return `<span id="${id}">${esc(ua.substring(0,max))}...</span> <a href="javascript:void(0)" onclick="
    var e=document.getElementById('${id}');
    if(e.dataset.expanded){
      e.innerHTML='${esc(ua.substring(0,max)).replace(/'/g,"\\'")}...';
      e.dataset.expanded='';
      this.textContent='展开';
    }else{
      e.innerHTML='${esc(ua).replace(/'/g,"\\'")}';
      e.dataset.expanded='1';
      this.textContent='收起';
    }
  ">展开</a>`;
}

function formatBytes(b) { if (!b || b <= 0) return '0 B'; const u = ['B','KB','MB','GB']; let i = 0; while (b >= 1024 && i < u.length-1) { b /= 1024; i++; } return b.toFixed(1) + ' ' + u[i]; }

function toggleHttpsDeps(prefix) {
  const https = gc(prefix + 'https');
  const sslId = gv(prefix + 'ssl-id');
  const enabled = https && sslId !== '';
  const deps = ['hsts', 'http2', 'http3', 'tls-1.2', 'tls-1.3'];
  deps.forEach(id => {
    const el = document.getElementById(prefix + id);
    if (!el) return;
    el.disabled = !enabled;
  });
  // Auto-check TLS 1.2 and 1.3 if enabled and none are checked
  if (enabled && !gc(prefix + 'tls-1.2') && !gc(prefix + 'tls-1.3')) {
    const t12 = document.getElementById(prefix + 'tls-1.2');
    const t13 = document.getElementById(prefix + 'tls-1.3');
    if (t12) t12.checked = true;
    if (t13) t13.checked = true;
  }
}

function tlsToChecked(versions) {
  const parts = (versions||'').split(' ');
  const res = {};
  ['TLSv1.2','TLSv1.3'].forEach(v => { res[v] = parts.includes(v); });
  return res;
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
});
