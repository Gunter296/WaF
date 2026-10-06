import {
    demoPolicy,
    demoLearning,
    demoHealth,
    demoLogs
} from './demo.js';

const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
} [c]));
const fmt = n => Number(n || 0).toLocaleString('vi-VN');
const date = s => s ? new Date(s).toLocaleString('vi-VN') : 'Chưa có';
const preview = new URLSearchParams(location.search).get('preview') === '1';
const themeStorageKey = 'ntvdt-portal-theme';
let theme = 'dark';
try {
    const stored = localStorage.getItem(themeStorageKey);
    if (stored === 'light' || stored === 'dark') theme = stored;
} catch {}
document.documentElement.dataset.theme = theme;
let policy, saved, learning = [],
    health = {},
    logs = [],
    logsMeta = { total: 0, page: 1, page_size: 25, pages: 1 },
    logsLoading = false,
    logsError = '',
    logQuery = '',
    logDataset = 'all',
    logCategory = 'all',
    logStatus = 'all',
    logEvent = '',
    logPath = '',
    logIp = '',
    logFrom = '',
    logTo = '',
    logPage = 1,
    logPitId = '',
    logCursors = [null],
    logSearchTimer,
    logRequestSeq = 0,
    dirty = false,
    busy = false,
    page = 1,
    search = '',
    filter = 'all';
const routes = {
    overview: ['◈', 'Tổng quan', 'Tổng quan bảo mật', 'Cấu hình phòng thủ và các tín hiệu cần đánh giá trong workspace.'],
    findings: ['☷', 'Hàng đợi phân tích', 'Hàng đợi phân tích', 'Đối chiếu ứng viên learning với request ID trước khi xác nhận false positive.'],
    policy: ['◇', 'WAF & CRS', 'Chính sách WAF & CRS', 'Điều khiển chế độ thực thi, paranoia level và virtual patch.'],
    bots: ['◎', 'Bot & hành vi', 'Bot & hành vi bất thường', 'Phân loại User-Agent, giới hạn lưu lượng và xử lý hành vi theo IP.'],
    access: ['⊞', 'IP & quốc gia', 'Kiểm soát IP & quốc gia', 'Quản lý IP, CIDR và dữ liệu quốc gia mô phỏng của lab.'],
    tuning: ['≋', 'Tuning rules', 'Tuning & ngoại lệ CRS', 'Ngoại lệ giới hạn theo website, rule, method, đường dẫn và tham số.'],
    automation: ['⟳', 'Learning & automation', 'Learning & automation', 'Duyệt bằng chứng và kiểm soát điều kiện thay đổi policy tự động.'],
    logs: ['≡', 'Nhật ký', 'Nhật ký hoạt động', 'Tra cứu log HAProxy, WAF và ứng dụng trong Elasticsearch.']
};
const currentRoute = () => Object.hasOwn(routes, location.hash.slice(1)) ? location.hash.slice(1) : 'overview';
const get = (obj, path) => path.split('.').reduce((o, k) => o?.[k], obj);

function set(obj, path, value) {
    const keys = path.split('.');
    const last = keys.pop();
    const parent = keys.reduce((o, k) => o[k], obj);
    parent[last] = value;
}

function notify(message, error = false) {
    $('#notice').hidden = false;
    $('#notice').className = error ? 'error' : '';
    $('#notice').textContent = message;
}

function markDirty() {
    dirty = JSON.stringify(policy) !== JSON.stringify(saved);
    $('#save-bar').hidden = !dirty;
}
async function api(url, options) {
    const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(20000)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
}
async function load() {
    if (dirty) {
        notify('Hãy lưu hoặc hủy thay đổi trước khi tải lại.', true);
        return;
    }
    $('#refresh').disabled = true;
    try {
        if (preview) {
            policy = structuredClone(saved || demoPolicy);
            learning = learning.length ? learning : structuredClone(demoLearning);
            health = demoHealth;
        } else {
            const data = await api('/api/policy');
            policy = data.document;
            const results = await Promise.allSettled([api('/api/learning'), api('/api/automation/status')]);
            learning = results[0].status === 'fulfilled' ? results[0].value : [];
            health = results[1].status === 'fulfilled' ? results[1].value : {};
            if (results.some(r => r.status === 'rejected')) notify('Policy đã tải; learning hoặc trạng thái worker chưa khả dụng. Số liệu thiếu không được xem là 0 sự kiện.', true);
        }
        saved = structuredClone(policy);
        $('#connection').textContent = preview ? 'Preview · dữ liệu mẫu' : 'API đã kết nối';
        $('#connection').className = 'badge';
        $('#updated').textContent = `Đồng bộ lúc ${new Date().toLocaleTimeString('vi-VN')} · Policy v${policy.version}`;
        render();
        if (currentRoute() === 'logs') await loadLogs();
    } catch (e) {
        $('#connection').textContent = 'Mất kết nối API';
        $('#connection').className = 'badge red';
        notify(`Không tải được dữ liệu: ${e.message}. Kiểm tra portal và PostgreSQL.`, true);
        if (!policy) $('#content').innerHTML = '<div class="panel empty">Chưa có dữ liệu từ portal.<br>Nhấn Làm mới sau khi dịch vụ hoạt động.</div>';
    } finally {
        $('#refresh').disabled = false;
    }
}
async function loadLogs() {
    const requestSeq = ++logRequestSeq;
    logsLoading = true;
    logsError = '';
    if (currentRoute() === 'logs') refreshLogPanel();
    try {
        const params = new URLSearchParams({ page: String(logPage), source: logDataset, category: logCategory, status: logStatus });
        if (logPitId) params.set('pit', logPitId);
        if (logPage > 1) params.set('after', JSON.stringify(logCursors[logPage - 1]));
        if (logQuery.trim()) params.set('q', logQuery.trim());
        if (logEvent.trim()) params.set('event', logEvent.trim());
        if (logPath.trim()) params.set('path', logPath.trim());
        if (logIp.trim()) params.set('ip', logIp.trim());
        if (logFrom) params.set('from', new Date(`${logFrom}T00:00:00`).toISOString());
        if (logTo) {
            const end = new Date(`${logTo}T00:00:00`);
            end.setDate(end.getDate() + 1);
            params.set('to', end.toISOString());
        }
        const data = preview ? previewLogData() : await api(`/api/logs?${params}`);
        if (requestSeq !== logRequestSeq) return;
        logs = data.items;
        logsMeta = data;
        logPitId = data.pit_id || '';
    } catch (error) {
        if (requestSeq === logRequestSeq) {
            if (logPage > 1 && /Elasticsearch returned 404/.test(error.message)) {
                resetLogPaging();
                notify('Phiên xem log đã hết hạn; đang tải lại trang đầu.', true);
                void loadLogs();
            } else logsError = error.message;
        }
    } finally {
        if (requestSeq === logRequestSeq) {
            logsLoading = false;
            if (currentRoute() === 'logs') refreshLogPanel();
        }
    }
}
function resetLogPaging() {
    logPage = 1;
    logPitId = '';
    logCursors = [null];
}
function previewLogData() {
    const categoryNames = { sqli: 'SQL injection', xss: 'XSS', rce: 'RCE', lfi: 'LFI', ssrf: 'SSRF', cve: 'CVE-' };
    const filtered = demoLogs.filter(row => {
        const info = row.portal;
        const group = info.source_group || 'other';
        const day = new Date(row['@timestamp']).toLocaleDateString('sv-SE');
        return (logDataset === 'all' || group === logDataset) &&
            (logCategory === 'all' || (info.category || '').includes(categoryNames[logCategory])) &&
            (logStatus === 'all' || (logStatus === '403' ? info.status === 403 : String(info.status).startsWith(logStatus[0]))) &&
            (!logFrom || day >= logFrom) && (!logTo || day <= logTo) &&
            (!logEvent || JSON.stringify(row.event || {}).toLowerCase().includes(logEvent.toLowerCase())) &&
            (!logPath || info.path.toLowerCase().includes(logPath.toLowerCase())) &&
            (!logIp || info.ip === logIp) &&
            (!logQuery || JSON.stringify(row).toLowerCase().includes(logQuery.toLowerCase()));
    });
    const pageSize = 25;
    const offset = (logPage - 1) * pageSize;
    return { items: filtered.slice(offset, offset + pageSize), total: filtered.length, page: logPage,
        page_size: pageSize, pages: Math.max(1, Math.ceil(filtered.length / pageSize)),
        pit_id: 'preview', next_after: offset + pageSize < filtered.length ? ['preview', offset + pageSize] : null };
}
function refreshLogPanel() {
    const panel = $('#content > .panel');
    if (panel) panel.outerHTML = logRows();
    else render();
}
async function save() {
    if (busy || !policy) return;
    const invalid = $('#content').querySelector(':invalid');
    if (invalid) {
        invalid.reportValidity();
        return;
    }
    busy = true;
    $('#save').disabled = true;
    try {
        if (preview) {
            policy.version++;
        } else policy = await api('/api/policy', {
            method: 'PUT',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify(policy)
        });
        saved = structuredClone(policy);
        dirty = false;
        markDirty();
        render();
        $('#updated').textContent = `Đồng bộ lúc ${new Date().toLocaleTimeString('vi-VN')} · Policy v${policy.version}`;
        notify(preview ? 'Đã lưu trong bản xem thử. WAF không bị thay đổi.' : 'Đã lưu policy. Ngoại lệ CRS được backend validate và reload khi cần.');
    } catch (e) {
        notify(`Chưa áp dụng: ${e.message}. Bản nháp vẫn được giữ; nếu version đã thay đổi, hãy hủy bản nháp rồi tải lại.`, true);
    } finally {
        busy = false;
        $('#save').disabled = false;
    }
}
const badge = (label, tone = '') => `<span class="badge ${tone}">${esc(label)}</span>`;
const panel = (title, body, extra = '') => `<section class="panel"><div class="panel-head"><h2>${title}</h2>${extra}</div><div class="panel-body">${body}</div></section>`;

function field(path, label, kind = 'number', options = {}) {
    const value = get(policy, path);
    const attr = `data-path="${esc(path)}" data-kind="${kind}"`;
    if (kind === 'checkbox') return `<label class="switch-field">${label}<input type="checkbox" ${attr} ${value?'checked':''}></label>`;
    let input;
    if (kind === 'select') input = `<select ${attr}>${options.values.map(v=>{const [key,title]=Array.isArray(v)?v:[v,v];return `<option value="${esc(key)}" ${String(value)===String(key)?'selected':''}>${esc(title)}</option>`;}).join('')}</select>`;
    else if (kind === 'list' || kind === 'json') input = `<textarea rows="${options.rows||3}" ${attr}>${esc(kind==='json'?JSON.stringify(value,null,2):(value||[]).join('\n'))}</textarea>`;
    else input = `<input ${attr} type="${kind}" value="${esc(value)}" ${kind==='number'?`min="${options.min??1}" max="${options.max??100000}" required`:''}>`;
    return `<label class="field ${options.wide?'wide':''}">${label}${input}${options.help?`<small>${options.help}</small>`:''}</label>`;
}
const grid = body => `<div class="field-grid">${body}</div>`;
const choice = (path, label, values) => field(path, label, 'select', {
    values
});
const toggle = (path, label) => field(path, label, 'checkbox');
const action = path => choice(path, 'Hành động', [
    ['observe', 'Quan sát'],
    ['block', 'Chặn khi WAF ở On']
]);

function render() {
    const route = currentRoute();
    const config = routes[route];
    $('#crumb').textContent = config[1];
    $('#page-title').textContent = config[2];
    $('#page-description').textContent = config[3];
    $('#navigation').innerHTML = Object.entries(routes).filter(([key]) => key !== 'logs').map(([key, r]) => `<a class="nav-item ${key===route?'active':''}" href="#${key}" ${key===route?'aria-current="page"':''}><span>${r[0]}</span>${r[1]}${key==='findings'&&learning.length?`<span class="nav-count">${learning.length}</span>`:''}</a>`).join('');
    $('#observability-navigation').innerHTML = `<a class="nav-item ${route==='logs'?'active':''}" href="#logs" ${route==='logs'?'aria-current="page"':''}><span>≡</span>Nhật ký</a>`;
    if (!policy) return;
    const renderers = {
        overview: overview,
        findings: findings,
        policy: policyView,
        bots: botsView,
        access: accessView,
        tuning: tuningView,
        automation: automationView,
        logs: logsView
    };
    $('#content').innerHTML = renderers[route]();
    markDirty();
}

function overview() {
    const pending = learning.filter(x => ['candidate', 'needs_review'].includes(x.status)).length;
    const active = policy.tuning_rules.filter(r => r.enabled !== false && new Date(r.expires_at) > new Date()).length;
    const counts = ['candidate', 'needs_review', 'confirmed_fp', 'dismissed'].map(s => learning.filter(x => x.status === s).length);
    const max = Math.max(...counts, 1);
    const labels = ['Ứng viên mới', 'Cần đánh giá', 'Đã xác nhận FP', 'Đã bỏ qua'];
    const severity = ['critical', 'high', 'medium', 'low'];
    const colors = ['#e99389', '#e6b55c', '#60c7cc', getComputedStyle(document.documentElement).getPropertyValue('--mint').trim() || '#00F5FF'];
    const totals = severity.map(s => learning.filter(x => x.document.severity === s).length);
    const total = totals.reduce((a, b) => a + b, 0);
    let cursor = 0;
    const gradient = totals.map((n, i) => {
        const start = cursor;
        cursor += n / (total || 1) * 100;
        return `${colors[i]} ${start}% ${cursor}%`;
    }).join(',');
    return `<div class="metrics">${[
    ['Chế độ thực thi',policy.mode==='On'?'Blocking':'Detection','Coraza & chính sách hành vi','◇'],
    ['Cần đánh giá',fmt(pending),'Ứng viên learning đang chờ','↗'],
    ['Ngoại lệ đang áp dụng',fmt(active),'Có phạm vi và thời hạn','≋'],
    ['Blocking / Detection PL',`${policy.blocking_pl}<em>/ ${policy.detection_pl}</em>`,'Paranoia level đã cấu hình','◈']
  ].map(([l,v,n,i])=>`<section class="metric"><div class="metric-label">${l}<span>${i}</span></div><div class="metric-value">${v}</div><div class="metric-note">${n}</div></section>`).join('')}</div>
  <div class="flow-strip"><span class="dot"></span><strong>Finance protection</strong><span>HAProxy</span><span>→</span><span>Coraza / CRS</span><span>→</span><span>Finance</span><span class="spacer"></span><span class="tag">CẤU HÌNH LAB</span><a href="http://127.0.0.1:5601" target="_blank" rel="noopener" aria-label="Mở Kibana để xem log WAF" title="Mở Kibana để xem log WAF">Mở Kibana ↗</a></div>
  <div class="two-col">${panel('Trạng thái phân tích',learning.length?`<div class="bar-chart">${counts.map((n,i)=>`<div class="bar-row"><span>${labels[i]}</span><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%"></div></div><span>${fmt(n)}</span></div>`).join('')}</div><div class="chart-caption"><span>Đơn vị: ứng viên learning</span><span>${learning.length} ứng viên đã tải</span></div>`:'<div class="chart-empty">Chưa có ứng viên learning để tổng hợp.</div>','<small>Snapshot hiện tại</small>')}
  ${panel('Mức độ của ứng viên',total?`<div class="donut-layout"><div class="donut" style="background:conic-gradient(${gradient})"><div class="donut-inner"><strong>${total}</strong><small>ỨNG VIÊN</small></div></div><div class="legend">${severity.map((s,i)=>`<div><i style="background:${colors[i]}"></i>${s}<strong>${totals[i]}</strong></div>`).join('')}</div></div>`:'<div class="chart-empty">Chưa có dữ liệu mức độ.</div>','<small>Learning worker</small>')}</div>
  <section class="panel"><div class="panel-head"><h2 class="queue-title"><i></i>Hàng đợi cần chú ý</h2><a href="#findings">Xem tất cả ↗</a></div>${learningTable(learning.slice(0,5),false)}<div class="table-footer"><span>Nguồn: /api/learning · Tối đa 200 ứng viên gần nhất</span><span>Không phải tổng số request</span></div></section>`;
}

function policyView() {
    return `<div class="equal-col">${panel('Chế độ & paranoia level',toggle('enabled','Bật các policy tùy chỉnh của lab')+grid(choice('mode','Chế độ WAF',[['On','On · Cho phép chặn'],['DetectionOnly','DetectionOnly · Ghi nhận']])+choice('blocking_pl','Blocking PL',[1,2,3,4])+choice('detection_pl','Detection PL',[1,2,3,4]))+'<p class="subtle">Tắt policy tùy chỉnh không tắt CRS. DetectionOnly ghi nhận thay vì chặn.</p>')}${panel('Virtual patch & fixture',toggle('cve_rules.CVE-2026-64642','CVE-2026-64642 · Middleware bypass')+toggle('cve_rules.CVE-2026-64645','CVE-2026-64645 · Rewrite SSRF')+toggle('crs_exclusions.sqli_search','Ngoại lệ 942100 tại /api/lab/search')+'<p class="subtle">Virtual patch khớp route fixture của lab. Ngoại lệ SQLi có thể làm bỏ sót tấn công tại endpoint này.</p>')}</div>${panel('Policy đang chỉnh sửa',`<details class="json-details"><summary>Xem toàn bộ JSON</summary><pre>${esc(JSON.stringify(policy,null,2))}</pre></details>`)}`;
}

function botsView() {
    return `<div class="hint">Bot detection dùng User-Agent tự khai báo và hành vi. Rate limit chung vẫn áp dụng với client giả User-Agent trình duyệt. Chọn “Chặn” và WAF On để thực thi.</div><div class="equal-col">${panel('Nhận diện bot & chống spam',toggle('bot_detection.enabled','Bật bot detection')+grid(field('bot_detection.spam_requests','Sức chứa token bucket','number',{max:10000})+field('bot_detection.spam_window_seconds','Thời gian nạp đầy bucket (giây)','number',{max:3600})+field('bot_detection.unique_paths','Số đường dẫn khác nhau','number',{min:3,max:100})+field('bot_detection.window_seconds','Cửa sổ quét đường dẫn (giây)','number',{max:3600})+action('bot_detection.action'))+'<p class="subtle">Ví dụ 10 token / 10 giây: burst tối đa 10, nạp lại 1 token/giây. Bộ đếm nằm trong tiến trình WAF.</p>')}${panel('Giới hạn request theo IP / CIDR',toggle('rate_limit.enabled','Bật rate limit chung')+grid(field('rate_limit.requests','Request / IP')+field('rate_limit.window_seconds','Cửa sổ / IP (giây)')+field('rate_limit.range_requests','Request / CIDR')+field('rate_limit.range_window_seconds','Cửa sổ / CIDR (giây)')+choice('rate_limit.prefix_v4','Prefix IP v4',[32,24,16,8])+choice('rate_limit.prefix_v6','Prefix IP v6',[128,64,48])+choice('rate_limit.range_prefix_v4','Prefix CIDR v4',[24,16,8])+choice('rate_limit.range_prefix_v6','Prefix CIDR v6',[64,48])))}</div>${Object.entries({login_failures:'Đăng nhập thất bại',not_found_burst:'Quét URL · Burst 404',sequential_documents:'Truy cập chứng từ tuần tự'}).map(([k,l])=>panel(l,toggle(`
    behavior.$ {
        k
    }.enabled`,'Bật xử lý hành vi')+grid(field(`
    behavior.$ {
        k
    }.limit`,'Số lần ghi nhận','number',{max:10000})+field(`
    behavior.$ {
        k
    }.window_seconds`,'Cửa sổ (giây)','number',{max:3600})+action(`
    behavior.$ {
        k
    }.action`)))).join('')}`;
}

function accessView() {
    return `<div class="hint">Danh sách IP/CIDR được portal kiểm tra rồi sinh rule Coraza @ipMatch; denylist ưu tiên trước allowlist. IP được cho phép vẫn qua CRS. Log chặn ghi mã quốc gia từ fixture Docker hoặc GeoIP MMDB nếu có; khi không tra được sẽ là ZZ. Allowlist để trống sẽ không giới hạn theo danh sách cho phép.</div><div class="equal-col">${panel('IP / CIDR',toggle('ip_policy.enabled','Bật chính sách IP / CIDR')+grid(field('ip_policy.deny','Danh sách chặn','list',{wide:true,help:'Mỗi dòng một IP hoặc CIDR.'})+field('ip_policy.allow','Danh sách cho phép','list',{wide:true})))}${panel('Quốc gia / GeoIP',toggle('geo.enabled','Bật country policy')+grid(field('geo.deny','Mã quốc gia chặn','list',{help:'Mỗi dòng một mã, ví dụ US.'})+field('geo.allow','Mã quốc gia cho phép','list')+field('geo.fixtures','Ánh xạ IP → mã quốc gia','json',{wide:true,rows:5})))}</div>`;
}

function tuningView() {
    return `<div class="hint">Ngoại lệ mới sẽ được lưu cùng policy khi bạn nhấn “Lưu và áp dụng”. Backend validate và reload Caddy; nếu reload lỗi, cấu hình đang chạy được giữ lại.</div><section class="panel"><div class="panel-head"><h2>Ngoại lệ CRS <span class="subtle">/ ${policy.tuning_rules.length}</span></h2><button class="primary" data-action="add-tuning">＋ Thêm ngoại lệ</button></div>${policy.tuning_rules.length?`<div class="table-wrap"><table><thead><tr><th>RULE / PHẠM VI</th><th>WEBSITE / ENDPOINT</th><th>LÝ DO</th><th>HẾT HẠN</th><th>TRẠNG THÁI</th><th></th></tr></thead><tbody>${policy.tuning_rules.map((r,i)=>`<tr><td><strong>${r.rule_id}</strong><br><span class="mono">${esc(r.target||'Toàn rule trên route')}</span></td><td>${esc(r.site)}<br><span class="mono">${esc(r.method)} ${esc(r.path)}</span></td><td>${esc(r.reason)}</td><td>${esc(date(r.expires_at))}</td><td>${badge(r.enabled===false?'Tạm tắt':new Date(r.expires_at)<new Date()?'Hết hạn':'Đang bật',r.enabled===false?'gray':'')}</td><td><div class="action-row"><button class="small" data-action="edit-tuning" data-index="${i}">Sửa</button><button class="small danger" data-action="remove-tuning" data-index="${i}">Thu hồi</button></div></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">Chưa có ngoại lệ CRS.<br>Tạo ngoại lệ sau khi xác minh false positive.</div>'}</section>`;
}

function automationView() {
    return `<div class="equal-col">${panel('Learning worker',`<div class="status-line"><span>Heartbeat gần nhất</span><strong>${esc(date(health.worker_last_seen))}</strong></div><div class="status-line"><span>Trạng thái heartbeat</span>${badge(!health.worker_last_seen?'Chưa có':Date.now()-new Date(health.worker_last_seen)>120000?'Quá 2 phút':'Gần đây',!health.worker_last_seen?'gray':'')}</div><div class="status-line"><span>Ứng viên đã tải</span><strong>${learning.length}</strong></div><div class="status-line"><span>Đang theo dõi thay đổi</span><strong>${policy.automation.transition?'Có':'Không'}</strong></div><p class="subtle">Worker đọc Elasticsearch mỗi 60 giây. <a href="#findings">Mở hàng đợi để đánh nhãn →</a></p>`)}${panel('Chế độ automation',grid(choice('automation.mode','Chế độ',[['manual','Manual · Chỉ đề xuất'],['automatic','Automatic · Theo điều kiện']])+choice('automation.target_pl','PL mục tiêu',[1,2,3,4]))+toggle('automation.flow_test_passed','Xác nhận kiểm thử luồng hợp lệ đã đạt')+toggle('automation.auto_exceptions','Cho phép ngoại lệ tham số tự động')+field('automation.approved_paths','Endpoint cho phép ngoại lệ tự động','list',{help:'Một đường dẫn chính xác mỗi dòng.'}))}</div><div class="hint">Nâng PL yêu cầu 7 ngày và 10.000 request, cùng xác nhận kiểm thử và không có false positive nghiêm trọng chưa xử lý. Ngoại lệ tự động cần bằng chứng do admin xác nhận. Theo dõi 15 phút sau thay đổi để rollback. UI không tự kích hoạt nâng PL.</div>`;
}

function learningTable(rows, actions = true) {
    if (!rows.length) return '<div class="empty">Không có ứng viên phù hợp.<br>Dữ liệu xuất hiện khi learning worker thu thập được sự kiện.</div>';
    return `<div class="table-wrap"><table><thead><tr><th>RULE / ENDPOINT</th><th>LOẠI</th><th>REQUEST ĐÃ GOM</th><th>MỨC ĐỘ</th><th>TRẠNG THÁI</th><th>${actions?'THAO TÁC':'PL'}</th></tr></thead><tbody>${rows.map(r=>{const d=r.document;return `<tr><td><span class="route-title">CRS ${esc(d.rule_id)} · ${esc(d.method)}</span><span class="mono">${esc(d.path)}</span></td><td>${badge(d.parameter||'Rule match','purple')}</td><td>${fmt(d.count)} <span class="subtle">/ ${fmt(d.days)} ngày</span></td><td>${badge(d.severity,['critical','high'].includes(d.severity)?'red':d.severity==='medium'?'amber':'gray')}</td><td>${badge(r.status,r.status==='confirmed_fp'?'':'gray')}</td><td>${actions?`<button class="small" data-action="review" data-key="${esc(r.key)}">Đánh giá ↗</button>`:esc('PL '+d.pl)}</td></tr>`;}).join('')}</tbody></table></div>`;
}

function findings() {
    const all = learning.filter(r => (filter === 'all' || r.status === filter) && JSON.stringify(r).toLowerCase().includes(search.toLowerCase()));
    const pages = Math.max(1, Math.ceil(all.length / 10));
    page = Math.min(page, pages);
    return `<div class="toolbar"><input id="search" type="search" aria-label="Tìm ứng viên" placeholder="Tìm rule ID, endpoint, request ID…" value="${esc(search)}"><select id="filter" aria-label="Lọc trạng thái">${['all','candidate','needs_review','confirmed_fp','dismissed','auto_applied'].map(s=>`<option ${filter===s?'selected':''}>${s}</option>`).join('')}</select><button data-action="export">↓ Xuất JSON</button></div><section class="panel"><div class="panel-head"><h2>Ứng viên learning <span class="subtle">/ ${all.length}</span></h2><small>Dữ liệu hiện có · không phải luồng log trực tiếp</small></div>${learningTable(all.slice((page-1)*10,page*10))}<div class="table-footer"><span>${all.length} kết quả · Tối đa 200 ứng viên từ API</span><div class="action-row"><button data-action="prev" ${page===1?'disabled':''}>←</button><span>${page} / ${pages}</span><button data-action="next" ${page===pages?'disabled':''}>→</button></div></div></section>`;
}

function logRows() {
    if (logsLoading) return '<section class="panel empty">Đang tải nhật ký…</section>';
    if (logsError) return `<section class="panel empty">Không tải được nhật ký: ${esc(logsError)}</section>`;
    if (!logs.length) return '<section class="panel empty">Không có sự kiện phù hợp trong khoảng ngày đã chọn. Thử mở rộng thời gian hoặc tạo request mới.</section>';
    return `<section class="panel logs-panel"><div class="panel-head"><h2>Nhật ký <span class="subtle">/ ${fmt(logsMeta.total)}</span></h2><small>Trang ${logsMeta.page} / ${logsMeta.pages} · ${logsMeta.page_size} bản ghi/trang</small></div><div class="logs-table-frame"><div class="table-wrap logs-table-wrap" tabindex="0" role="region" aria-label="Bảng nhật ký cuộn ngang"><table class="logs-table"><thead><tr><th>NGÀY / GIỜ</th><th>NGUỒN</th><th>SỰ KIỆN</th><th>PHÂN LOẠI</th><th>ĐƯỜNG DẪN / IP</th><th>HTTP</th><th>CHI TIẾT</th></tr></thead><tbody>${logs.map(row => {
        const info = row.portal || {};
        const event = info.explanation || row?.event?.action || row?.rule?.id || (typeof row.message === 'string' ? row.message.slice(0, 140) : '') || 'request';
        const route = info.correlation?.haproxy?.route || row?.lab?.route || '';
        return `<tr><td>${esc(date(row?.['@timestamp']))}</td><td>${esc(info.source_label || 'Không rõ nguồn')}</td><td>${esc(event)}</td><td>${esc(info.category || 'Chưa phân loại')}${info.rules?.length ? `<br><span class="subtle">Rule ${esc(info.rules.join(', '))}</span>` : ''}${info.matches?.length ? `<br><span class="mono">${esc(info.matches[0])}</span>` : ''}</td><td><span class="mono">${esc(info.path || '')}</span><br><span class="subtle">${esc(info.ip || '')}</span>${route ? `<br><span class="subtle">Tuyến: ${esc(route)}</span>` : ''}</td><td>${info.blocked ? '<span class="status-badge denied">Đã chặn</span>' : esc(info.status ?? '—')}</td><td><details class="json-details"><summary>Xem JSON</summary><pre>${esc(JSON.stringify(row, null, 2))}</pre></details></td></tr>`;
    }).join('')}</tbody></table></div><div class="logs-scroll-control"><label for="logs-scroll-slider">Cuộn ngang bảng nhật ký</label><input id="logs-scroll-slider" type="range" min="0" max="100" step="1" value="0" aria-label="Thanh cuộn ngang bảng nhật ký"></div></div><div class="table-footer"><span>Hiển thị ${Math.min((logsMeta.page - 1) * logsMeta.page_size + 1, logsMeta.total)}–${Math.min(logsMeta.page * logsMeta.page_size, logsMeta.total)} / ${fmt(logsMeta.total)}</span><div class="action-row"><button data-action="log-prev" ${logsMeta.page <= 1 ? 'disabled' : ''}>← Trước</button><button data-action="log-next" ${!logsMeta.next_after ? 'disabled' : ''}>Sau →</button></div></div></section>`;
}

function logsView() {
    const sources = [['all','Tất cả nguồn'],['haproxy','HAProxy'],['waf','WAF / Coraza'],['finance','Finance'],['portal','Portal'],['other','Khác / chưa phân loại']];
    const categories = [['all','Mọi loại'],['sqli','SQL injection'],['xss','XSS'],['rce','RCE'],['lfi','LFI'],['ssrf','SSRF'],['cve','CVE']];
    const statuses = [['all','Mọi HTTP'],['2xx','2xx'],['3xx','3xx'],['4xx','4xx'],['5xx','5xx'],['403','403']];
    return `<div class="toolbar logs-toolbar"><input id="log-search" type="search" aria-label="Tìm trong nhật ký" placeholder="Tìm request ID, IP, rule, đường dẫn…" value="${esc(logQuery)}"><label>Từ ngày <input id="log-from" type="date" value="${esc(logFrom)}"></label><label>Đến ngày <input id="log-to" type="date" value="${esc(logTo)}"></label></div><div class="logs-column-filters" aria-label="Lọc theo cột"><label>Nguồn<select id="log-dataset" aria-label="Lọc nguồn nhật ký">${sources.map(([value,label]) => `<option value="${value}" ${logDataset===value?'selected':''}>${label}</option>`).join('')}</select></label><label>Sự kiện<input id="log-event" type="search" placeholder="Tên sự kiện" value="${esc(logEvent)}"></label><label>Payload / CVE<select id="log-category">${categories.map(([value,label]) => `<option value="${value}" ${logCategory===value?'selected':''}>${label}</option>`).join('')}</select></label><label>Đường dẫn<input id="log-path" type="search" placeholder="/api/..." value="${esc(logPath)}"></label><label>IP<input id="log-ip" type="search" placeholder="IP chính xác" value="${esc(logIp)}"></label><label>HTTP<select id="log-status">${statuses.map(([value,label]) => `<option value="${value}" ${logStatus===value?'selected':''}>${label}</option>`).join('')}</select></label></div><p class="subtle logs-help">“Khác / chưa phân loại” là sự kiện không thuộc HAProxy, WAF/Coraza, Finance hoặc Portal. Khi có tên dataset/tệp, tên đó vẫn hiện ở cột Nguồn; “Không rõ nguồn” nghĩa là log thiếu thông tin nhận dạng. /healthz bị loại khỏi bảng vì đây là yêu cầu kiểm tra trạng thái dịch vụ. Mở JSON log WAF để xem ngữ cảnh HAProxy liên kết theo request ID.</p>${logRows()}`;
}

function dialog(title, html, onSubmit) {
    $('#dialog-title').textContent = title;
    $('#dialog-body').innerHTML = html;
    $('#dialog-error').textContent = '';
    $('#dialog-form').onsubmit = async e => {
        e.preventDefault();
        const button = e.submitter;
        button.disabled = true;
        try {
            await onSubmit(new FormData(e.target));
            $('#dialog').close();
        } catch (err) {
            $('#dialog-error').textContent = err.message;
        } finally {
            button.disabled = false;
        }
    };
    $('#dialog').showModal();
}

function tuningDialog(index) {
    const existing = index === undefined ? null : policy.tuning_rules[index];
    const r = existing || {
        site: 'finance-vulnerable',
        rule_id: 942100,
        method: 'GET',
        path: '/api/lab/search',
        scope: 'target',
        target: 'ARGS:q',
        reason: '',
        enabled: true,
        expires_at: new Date(Date.now() + 86400000).toISOString()
    };
    const input = (name, label, type = 'text', value = r[name]) => `<label class="field">${label}<input name="${name}" type="${type}" value="${esc(value)}" required></label>`;
    const select = (name, label, values) => `<label class="field">${label}<select name="${name}">${values.map(v=>`<option ${r[name]===v?'selected':''}>${v}</option>`).join('')}</select></label>`;
    const expiry = new Date(r.expires_at);
    const local = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    dialog(existing ? 'Sửa ngoại lệ CRS' : 'Thêm ngoại lệ CRS', grid(select('site', 'Website', ['finance-vulnerable', 'finance-patched']) + input('rule_id', 'CRS rule ID', 'number') + select('method', 'Method', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) + input('path', 'Đường dẫn chính xác') + select('scope', 'Phạm vi', ['target', 'rule']) + `<label class="field">Target<input name="target" value="${esc(r.target)}"><small>Để trống khi chọn phạm vi rule.</small></label>` + input('expires_at', 'Hết hạn', 'datetime-local', local) + `<label class="switch-field">Bật ngoại lệ<input name="enabled" type="checkbox" ${r.enabled!==false?'checked':''}></label>` + `<label class="field wide">Lý do và bằng chứng<textarea name="reason" required minlength="5" maxlength="200">${esc(r.reason)}</textarea></label>`), async f => {
        const expires = new Date(f.get('expires_at'));
        if (expires <= new Date() || expires > Date.now() + 30 * 86400000) throw new Error('Thời hạn phải ở tương lai và trong 30 ngày.');
        const next = {
            ...r,
            id: r.id || crypto.randomUUID(),
            rule_id: Number(f.get('rule_id')),
            site: f.get('site'),
            method: f.get('method'),
            path: f.get('path'),
            scope: f.get('scope'),
            target: f.get('scope') === 'target' ? f.get('target') : '',
            reason: f.get('reason'),
            expires_at: expires.toISOString(),
            enabled: f.has('enabled')
        };
        if (existing) policy.tuning_rules[index] = next;
        else policy.tuning_rules.push(next);
        markDirty();
        render();
    });
}

function review(key) {
    const row = learning.find(r => r.key === key);
    if (!row) return;
    const d = row.document;
    dialog('Đánh giá ứng viên learning', `<p class="evidence">${esc(d.method)} ${esc(d.path)} · CRS ${esc(d.rule_id)}<br>Tham số: ${esc(d.parameter)}<br>Từ ${esc(date(d.first_seen))} đến ${esc(date(d.last_seen))}<br>Request ID: ${esc((d.sample_request_ids||[]).join(', '))}<br>Dự kiến chịu ảnh hưởng ở PL cao hơn: ${fmt(d.estimated_blocks)}</p><div class="hint">HTTP 2xx không chứng minh false positive. Đối chiếu request ID, log ứng dụng và kiểm thử hợp lệ trước khi xác nhận.</div><label class="field">Nhãn<select name="status"><option value="needs_review">Cần xem lại</option><option value="confirmed_fp">Xác nhận false positive</option><option value="dismissed">Bỏ qua</option></select></label><label class="field">Bằng chứng<textarea name="evidence" rows="4" maxlength="500">${esc(row.review_note||'')}</textarea></label>`, async f => {
        const status = f.get('status'),
            evidence = String(f.get('evidence')).trim();
        if (status === 'confirmed_fp' && evidence.length < 12) throw new Error('Cần ít nhất 12 ký tự mô tả bằng chứng xác nhận.');
        if (!preview) await api(`/api/learning/${key}/label`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json'
            },
            body: JSON.stringify({
                status,
                evidence
            })
        });
        row.status = status;
        row.review_note = evidence;
        render();
        notify(preview ? 'Nhãn được cập nhật trong bản xem thử.' : 'Đã cập nhật nhãn learning.');
    });
}
$('#content').addEventListener('change', e => {
    const t = e.target;
    if (t.dataset.path) {
        let value = t.type === 'checkbox' ? t.checked : t.value;
        try {
            if (t.dataset.kind === 'number' || (t.tagName === 'SELECT' && typeof get(policy, t.dataset.path) === 'number')) value = Number(value);
            if (t.dataset.kind === 'list') value = value.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
            if (t.dataset.kind === 'json') {
                value = JSON.parse(value);
                if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('Cần JSON object ánh xạ IP sang quốc gia.');
            }
            t.setCustomValidity('');
            set(policy, t.dataset.path, value);
            markDirty();
        } catch (err) {
            t.setCustomValidity(err.message);
            t.reportValidity();
        }
    }
    if (t.id === 'filter') {
        filter = t.value;
        page = 1;
        render();
    }
    if (t.id === 'log-dataset' || t.id === 'log-category' || t.id === 'log-status') {
        clearTimeout(logSearchTimer);
        if (t.id === 'log-dataset') logDataset = t.value;
        if (t.id === 'log-category') logCategory = t.value;
        if (t.id === 'log-status') logStatus = t.value;
        resetLogPaging();
        void loadLogs();
    }
    if (t.id === 'log-from' || t.id === 'log-to') {
        clearTimeout(logSearchTimer);
        logFrom = $('#log-from').value;
        logTo = $('#log-to').value;
        resetLogPaging();
        void loadLogs();
    }
});
$('#content').addEventListener('input', e => {
    if (e.target.id === 'logs-scroll-slider') {
        const tableWrap = e.target.closest('.logs-table-frame')?.querySelector('.logs-table-wrap');
        if (tableWrap) tableWrap.scrollLeft = (tableWrap.scrollWidth - tableWrap.clientWidth) * Number(e.target.value) / 100;
    }
    if (e.target.id === 'search') {
        search = e.target.value;
        page = 1;
        const template = document.createElement('template');
        template.innerHTML = findings();
        $('#content > .panel').replaceWith(template.content.querySelector('.panel'));
    }
    if (['log-search','log-event','log-path','log-ip'].includes(e.target.id)) {
        if (e.target.id === 'log-search') logQuery = e.target.value;
        if (e.target.id === 'log-event') logEvent = e.target.value;
        if (e.target.id === 'log-path') logPath = e.target.value;
        if (e.target.id === 'log-ip') logIp = e.target.value;
        resetLogPaging();
        clearTimeout(logSearchTimer);
        logSearchTimer = setTimeout(() => { if (currentRoute() === 'logs') void loadLogs(); }, 350);
    }
});
$('#content').addEventListener('scroll', e => {
    if (!e.target.matches?.('.logs-table-wrap')) return;
    const slider = e.target.closest('.logs-table-frame')?.querySelector('#logs-scroll-slider');
    const maxScroll = e.target.scrollWidth - e.target.clientWidth;
    if (slider && maxScroll > 0) slider.value = String(Math.round(e.target.scrollLeft / maxScroll * 100));
}, true);
$('#content').addEventListener('click', e => {
    const b = e.target.closest('[data-action]');
    if (!b) return;
    switch (b.dataset.action) {
        case 'add-tuning':
            tuningDialog();
            break;
        case 'edit-tuning':
            tuningDialog(Number(b.dataset.index));
            break;
        case 'remove-tuning':
            policy.tuning_rules.splice(Number(b.dataset.index), 1);
            markDirty();
            render();
            break;
        case 'review':
            review(b.dataset.key);
            break;
        case 'prev':
            page--;
            render();
            break;
        case 'next':
            page++;
            render();
            break;
        case 'log-prev':
            logPage = Math.max(1, logPage - 1);
            void loadLogs();
            break;
        case 'log-next':
            if (!logsMeta.next_after) break;
            logCursors[logPage] = logsMeta.next_after;
            logPage++;
            void loadLogs();
            break;
        case 'export': {
            const blob = new Blob([JSON.stringify(learning.filter(r => (filter === 'all' || r.status === filter) && JSON.stringify(r).toLowerCase().includes(search.toLowerCase())), null, 2)], {
                type: 'application/json'
            });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = preview ? 'learning-demo.json' : 'learning.json';
            a.click();
            setTimeout(() => URL.revokeObjectURL(a.href), 1000);
            break;
        }
    }
});
$('#refresh').onclick = () => {
    if (!dirty) $('#notice').hidden = true;
    if (currentRoute() === 'logs') { resetLogPaging(); loadLogs(); }
    else load();
};
$('#save').onclick = save;
$('#discard').onclick = () => {
    policy = structuredClone(saved);
    markDirty();
    render();
    notify('Đã hủy bản nháp.');
};
$('#menu').onclick = () => document.body.classList.toggle('menu-open');
$('#close-dialog').onclick = $('#cancel-dialog').onclick = () => $('#dialog').close();

function setTheme(next) {
    theme = next;
    document.documentElement.dataset.theme = next;
    try {
        localStorage.setItem(themeStorageKey, next);
    } catch {}
    const light = next === 'light';
    $('#theme-icon').textContent = light ? '☼' : '◐';
    $('#theme-label').textContent = light ? 'Sáng' : 'Tối';
    $('#theme-toggle').setAttribute('aria-label', light ? 'Chuyển sang giao diện tối' : 'Chuyển sang giao diện sáng');
}
$('#theme-toggle').onclick = () => setTheme(theme === 'dark' ? 'light' : 'dark');
setTheme(theme);
window.addEventListener('hashchange', () => {
    document.body.classList.remove('menu-open');
    render();
    if (currentRoute() === 'logs') { resetLogPaging(); void loadLogs(); }
    window.scrollTo(0, 0);
});
window.addEventListener('beforeunload', e => {
    if (dirty) {
        e.preventDefault();
        e.returnValue = '';
    }
});
$('#preview-banner').hidden = !preview;
render();
load();
