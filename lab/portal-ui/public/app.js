import {
    demoPolicy,
    demoLearning,
    demoHealth,
    demoLogs
} from './demo.js';
import { escapeHtml, investigateRequest, redactLog, redactText, renderInvestigationDecisions, requestIdOf } from './log-investigation.mjs';

const $ = s => document.querySelector(s);
const esc = escapeHtml;
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
    overviewTimeline = null,
    overviewLoading = false,
    overviewRequest = null,
    learningLoading = false,
    overviewRange = 'day',
    logs = [],
    logReviews = {},
    logsMeta = { total: 0, page: 1, page_size: 25, pages: 1 },
    logsRenderSignature = '',
    logsLoading = false,
    logsError = '',
    logQuery = '',
    logDataset = 'all',
    logCategory = 'all',
    logSeverity = 'all',
    logSignal = false,
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
    traceCache = new Map(),
    tracePending = new Map(),
    dirty = false,
    busy = false,
    page = 1,
    search = '',
    filter = 'all';
const routes = {
    overview: ['◈', 'Tổng quan', 'Tổng quan bảo mật', 'Cấu hình phòng thủ và các tín hiệu cần đánh giá trong workspace.'],
    findings: ['☷', 'Hàng đợi phân tích', 'Hàng đợi phân tích', 'Đối chiếu ứng viên learning với request ID trước khi xác nhận false positive.'],
    policy: ['◇', 'WAF & CRS', 'Chính sách WAF & CRS', 'Điều khiển chế độ WAF, paranoia level, virtual patch và ngoại lệ CRS.'],
    bots: ['◎', 'Bot & hành vi', 'Bot & hành vi bất thường', 'Phân loại User-Agent, giới hạn lưu lượng và xử lý hành vi theo IP.'],
    access: ['⊞', 'IP & quốc gia', 'Kiểm soát IP & quốc gia', 'Quản lý IP, CIDR và dữ liệu quốc gia mô phỏng của lab.'],
    automation: ['⟳', 'Learning & automation', 'Learning & automation', 'Duyệt bằng chứng và kiểm soát điều kiện thay đổi policy tự động.'],
    logs: ['≡', 'Nhật ký', 'Nhật ký hoạt động', 'Tra cứu log HAProxy, WAF và ứng dụng trong Elasticsearch.']
};
const currentRoute = () => location.hash.slice(1) === 'tuning' ? 'policy' : Object.hasOwn(routes, location.hash.slice(1)) ? location.hash.slice(1) : 'overview';
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
async function loadOverview() {
    if (preview) return;
    if (overviewRequest) return overviewRequest;
    overviewLoading = true;
    if (policy && currentRoute() === 'overview') render();
    overviewRequest = api('/api/overview/logs').then(data => { overviewTimeline = data; }).catch(error => {
        notify(`Không tải được thống kê log: ${error.message}`, true);
    }).finally(() => {
        overviewLoading = false;
        overviewRequest = null;
        if (policy && currentRoute() === 'overview') render();
    });
    return overviewRequest;
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
            overviewTimeline = demoOverviewTimeline();
        } else {
            const data = await api('/api/policy');
            policy = data.document;
            saved = structuredClone(policy);
            learningLoading = true;
            $('#connection').textContent = 'API đã kết nối';
            $('#connection').className = 'badge';
            $('#updated').textContent = `Đồng bộ lúc ${new Date().toLocaleTimeString('vi-VN')} · Policy v${policy.version}`;
            render();
            if (currentRoute() === 'logs') void loadLogs();
            if (currentRoute() === 'overview') void loadOverview();
            const results = await Promise.allSettled([api('/api/learning'), api('/api/automation/status')]);
            learning = results[0].status === 'fulfilled' ? results[0].value : [];
            health = results[1].status === 'fulfilled' ? results[1].value : {};
            learningLoading = false;
            if (results.some(r => r.status === 'rejected')) notify('Policy đã tải; một phần learning hoặc trạng thái worker chưa khả dụng.', true);
        }
        saved = structuredClone(policy);
        $('#connection').textContent = preview ? 'Preview · dữ liệu mẫu' : 'API đã kết nối';
        $('#connection').className = 'badge';
        $('#updated').textContent = `Đồng bộ lúc ${new Date().toLocaleTimeString('vi-VN')} · Policy v${policy.version}`;
        render();
    } catch (e) {
        $('#connection').textContent = 'Mất kết nối API';
        $('#connection').className = 'badge red';
        notify(`Không tải được dữ liệu: ${e.message}. Kiểm tra portal và PostgreSQL.`, true);
        if (!policy) $('#content').innerHTML = '<div class="panel empty">Chưa có dữ liệu từ portal.<br>Nhấn Làm mới sau khi dịch vụ hoạt động.</div>';
    } finally {
        $('#refresh').disabled = false;
    }
}
async function loadLogs({ quiet = false } = {}) {
    if (quiet && logsLoading) return;
    const requestSeq = ++logRequestSeq;
    logsLoading = true;
    if (!quiet) {
        logsError = '';
        if (currentRoute() === 'logs') refreshLogPanel();
    }
    let changed = false;
    try {
        const params = new URLSearchParams({ page: String(logPage), source: logDataset, category: logCategory, severity: logSeverity, status: logStatus });
        if (logSignal) params.set('signal', '1');
        if (logPitId) params.set('pit', logPitId);
        if (logPage > 1) params.set('after', JSON.stringify(logCursors[logPage - 1]));
        if (logQuery.trim()) params.set('q', logQuery.trim());
        if (logEvent.trim()) params.set('event', logEvent.trim());
        if (logPath.trim()) params.set('path', logPath.trim());
        if (logIp.trim()) params.set('ip', logIp.trim());
        if (logFrom) params.set('from', new Date(`${logFrom}:00+07:00`).toISOString());
        if (logTo) params.set('to', new Date(`${logTo}:00+07:00`).toISOString());
        if (logFrom && logTo && Date.parse(params.get('from')) >= Date.parse(params.get('to'))) throw new Error('Thời điểm kết thúc phải sau thời điểm bắt đầu.');
        const data = preview ? previewLogData() : await api(`/api/logs?${params}`);
        if (requestSeq !== logRequestSeq) return;
        if (logPage > 1 && (!data.items.length || data.page > data.pages)) {
            resetLogPaging();
            notify('Trang nhật ký cũ không còn bản ghi; đang tải lại trang đầu.');
            void loadLogs();
            return;
        }
        const signature = JSON.stringify({ items: data.items, total: data.total, page: data.page,
            page_size: data.page_size, pages: data.pages, next_after: data.next_after });
        changed = signature !== logsRenderSignature;
        logsRenderSignature = signature;
        logs = data.items;
        logReviews = data.reviews || (preview ? logReviews : {});
        logsMeta = data;
        logPitId = data.pit_id || '';
    } catch (error) {
        if (requestSeq === logRequestSeq) {
            if (logPage > 1 && /Elasticsearch returned 404/.test(error.message)) {
                resetLogPaging();
                notify('Phiên xem log đã hết hạn; đang tải lại trang đầu.', true);
                void loadLogs();
            } else if (!quiet || !logs.length) logsError = error.message;
        }
    } finally {
        if (requestSeq === logRequestSeq) {
            logsLoading = false;
            if (currentRoute() === 'logs' && (!quiet || changed || !logs.length)) refreshLogPanel();
        }
    }
}
function resetLogPaging() {
    logPage = 1;
    logPitId = '';
    logCursors = [null];
}
function previewLogData() {
    const filtered = demoLogs.filter(row => {
        const info = row.portal;
        const group = info.source_group || 'other';
        const category = info.category_key || ({ 'SQL injection': 'sqli', 'XSS': 'xss', 'Command injection / RCE': 'rce', 'Path traversal / LFI': 'lfi', 'SSRF': 'ssrf' }[info.category]) ||
            (/^CVE-\d{4}-\d+/i.test(info.category || '') ? 'cve' : ['portal.audit','finance.lab','haproxy.system'].includes(row.event?.dataset) && row.event?.action ? 'other' : 'unclassified');
        const timestamp = Date.parse(row['@timestamp'] || '');
        const ruleId = String(info.rules?.[0] || '');
        const ruleCandidate = demoLearning.find(item => String(item.document.rule_id) === ruleId)?.document;
        const rawCode = ruleCandidate?.severity_syslog == null ? NaN : Number(ruleCandidate.severity_syslog);
        const severityName = demoSeverityKey(row, Number.isInteger(rawCode) ? rawCode : undefined);
        const severityGroup = ['emergency','alert'].includes(severityName) ? 'alert' : ['critical','error'].includes(severityName) ? 'high' : severityName === 'warning' ? 'warning' : ['notice','info','debug'].includes(severityName) ? 'informational' : 'unknown';
        const eventFields = `${row.event?.action || ''} ${row.event?.dataset || ''}`.toLowerCase();
        const searchable = [row.message, row.http?.request?.id, row.url?.path, row.request?.uri, row.transaction?.id, info.ip,
            row.transaction?.request?.uri, row.rule?.id, ...(info.rules || []), ...(info.matches || []), ...(row.transaction?.messages || []).flatMap(message => [message.message, message.details?.ruleId, message.details?.id, message.details?.data, message.details?.match])]
            .filter(Boolean).join(' ').toLowerCase();
        return (!logSignal || (group === 'waf' && (info.blocked || info.category))) &&
            (logDataset === 'all' || group === logDataset) &&
            (logCategory === 'all' || category === logCategory) &&
            (logStatus === 'all' || (logStatus === '403' ? info.status === 403 : String(info.status).startsWith(logStatus[0]))) &&
            (!logSeverity || logSeverity === 'all' || (group === 'waf' && severityGroup === logSeverity)) &&
            (!logFrom || timestamp >= Date.parse(`${logFrom}:00+07:00`)) &&
            (!logTo || timestamp < Date.parse(`${logTo}:00+07:00`)) &&
            (!logEvent || eventFields.includes(logEvent.toLowerCase())) &&
            (!logPath || String(info.path || row.url?.path || row.request?.uri || row.transaction?.request?.uri || '').toLowerCase().includes(logPath.toLowerCase())) &&
            (!logIp || info.ip === logIp) &&
            (!logQuery || searchable.includes(logQuery.toLowerCase()));
    });
    const pageSize = 25;
    const offset = (logPage - 1) * pageSize;
    return { items: filtered.slice(offset, offset + pageSize), total: filtered.length, page: logPage,
        page_size: pageSize, pages: Math.max(1, Math.ceil(filtered.length / pageSize)),
        pit_id: 'preview', next_after: offset + pageSize < filtered.length ? ['preview', offset + pageSize] : null };
}
function refreshLogPanel() {
    const panel = $('#logs-results');
    if (!panel) { render(); return; }
    const table = panel.querySelector('.logs-table-wrap');
    const scroll = table ? { top: table.scrollTop, left: table.scrollLeft } : null;
    const openKeys = [...panel.querySelectorAll('details[data-log-key][open]')].map(details => details.dataset.logKey);
    panel.innerHTML = logRows();
    const nextTable = panel.querySelector('.logs-table-wrap');
    if (scroll && nextTable) {
        nextTable.scrollTop = scroll.top;
        nextTable.scrollLeft = scroll.left;
    }
    for (const details of panel.querySelectorAll('details[data-log-key]')) {
        if (openKeys.includes(details.dataset.logKey)) details.open = true;
    }
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
        automation: automationView,
        logs: logsView
    };
    $('#content').innerHTML = renderers[route]();
    markDirty();
}

const syslogScale = [
    ['0', 'Emergency', '#a83e48'], ['1', 'Alert', '#bd514a'],
    ['2', 'Critical', '#d36a58'], ['3', 'Error', '#df8b58'],
    ['4', 'Warning', '#e6b55c'], ['5', 'Notice', '#60c7cc'],
    ['6', 'Informational', '#6fa9b4'], ['7', 'Debug', '#829096']
];
const syslogNameToCode = { emergency: 0, alert: 1, critical: 2, error: 3, warning: 4, notice: 5, informational: 6, info: 6, debug: 7 };

function severityInfo(value, isOriginalSource = false) {
    const raw = String(value ?? 'unknown').trim().toLowerCase();
    const code = /^\d$/.test(raw) ? Number(raw) : isOriginalSource ? syslogNameToCode[raw] : undefined;
    if (Number.isInteger(code) && code >= 0 && code <= 7) {
        const [number, name, color] = syslogScale[code];
        return { key: `syslog-${number}`, code, label: name, color, title: `${name} · Syslog severity ${number}` };
    }
    const legacy = {
        critical: ['Cũ: “critical” · không lưu đủ mã gốc', '#d36a58', 'Worker cũ gộp mã 0–1 thành critical; nếu nguồn là chữ Critical thì tương ứng mã 2. Bản ghi cũ không còn đủ dữ liệu để phân biệt.'],
        high: ['Cũ: “high” · có thể là Syslog 2–3', '#df8b58', 'Bản cũ gộp Syslog 2–3 thành high; mã gốc cần xem lại từ audit log.'],
        medium: ['Nhãn mẫu cũ: medium', '#e6b55c', 'Nhãn mẫu trước đây, không phải mức Syslog.'],
        low: ['Nhãn mẫu cũ: low', '#60c7cc', 'Nhãn mẫu trước đây, không phải mức Syslog.']
    };
    if (legacy[raw]) return { key: `legacy-${raw}`, label: legacy[raw][0], color: legacy[raw][1], title: legacy[raw][2] };
    if (/^-\d+$/.test(raw)) return { key: 'invalid-negative', label: `Không thuộc Syslog (${raw})`, color: '#829096', title: 'Syslog severity hợp lệ là 0–7. Giá trị âm không phải severity CRS; cần xem lại nguồn dữ liệu.' };
    return { key: 'unknown', label: 'Chưa xác định', color: '#829096', title: `Giá trị severity gốc: ${raw}` };
}

function candidateSeverityInfo(document) {
    if (Number.isInteger(document.severity_syslog)) return severityInfo(document.severity_syslog);
    if (document.severity_source !== undefined && document.severity_source !== null) return severityInfo(document.severity_source, true);
    return severityInfo(document.severity);
}

function candidateSeverityBadge(document) {
    const info = candidateSeverityInfo(document);
    const tone = ['syslog-0', 'syslog-1', 'syslog-2', 'syslog-3', 'legacy-critical', 'legacy-high'].includes(info.key) ? 'red' : info.key === 'syslog-4' || info.key === 'legacy-medium' ? 'amber' : 'gray';
    return `<span class="badge ${tone}" title="${esc(info.title)}">${esc(info.label)}</span>`;
}

function candidatePriorityCode(document) {
    const info = candidateSeverityInfo(document);
    if (Number.isInteger(info.code)) return info.code;
    return ({ 'legacy-critical': 1, 'legacy-high': 3, 'legacy-medium': 4, 'legacy-low': 6 })[info.key] ?? 9;
}

const overviewZone = 'Asia/Ho_Chi_Minh';
const overviewSeverityRows = [
    { key: 'alert', label: 'Khẩn cấp / cảnh báo', codes: ['emergency', 'alert'], color: '#d65f57' },
    { key: 'high', label: 'Nghiêm trọng / lỗi', codes: ['critical', 'error'], color: '#df8b58' },
    { key: 'warning', label: 'Cảnh báo', codes: ['warning'], color: '#e6b55c' },
    { key: 'informational', label: 'Thông tin', codes: ['notice', 'info', 'debug'], color: '#60c7cc' },
    { key: 'unknown', label: 'Chưa phân loại', codes: ['unknown'], color: '#829096' }
];
const overviewCategoryRows = [
    ['cve', 'CVE'], ['sqli', 'SQLi'], ['xss', 'XSS'], ['rce', 'Command / RCE'],
    ['lfi', 'Path / LFI'], ['ssrf', 'SSRF'], ['bot', 'Bot'], ['rate_limit', 'Rate limit'],
    ['scanner', 'Scanner'], ['behavior', 'Behavior'], ['other', 'Khác'], ['unclassified', 'Chưa phân loại']
];

function localParts(value) {
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone: overviewZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', hourCycle: 'h23' }).formatToParts(new Date(value));
    return Object.fromEntries(parts.filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
}

function localDatetime(value) {
    const parts = localParts(value);
    const minute = new Intl.DateTimeFormat('en-CA', { timeZone: overviewZone, minute: '2-digit' }).format(new Date(value));
    return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${minute}`;
}

function overviewColumns(range, now = new Date()) {
    const parts = localParts(now);
    const year = Number(parts.year), month = Number(parts.month), day = Number(parts.day);
    if (range === 'day') return Array.from({ length: 24 }, (_, hour) => {
        const from = new Date(Date.UTC(year, month - 1, day, hour) - 7 * 3600000);
        return { key: `${parts.year}-${parts.month}-${parts.day}T${String(hour).padStart(2, '0')}`, label: `${String(hour).padStart(2, '0')}h`, from, to: new Date(from.getTime() + 3600000) };
    });
    if (range === 'week') {
        const today = new Date(Date.UTC(year, month - 1, day));
        const monday = new Date(today.getTime() - ((today.getUTCDay() + 6) % 7) * 86400000);
        return Array.from({ length: 7 }, (_, index) => {
            const date = new Date(monday.getTime() + index * 86400000);
            const key = `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(date.getUTCDate()).padStart(2, '0')}`;
            const from = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) - 7 * 3600000);
            return { key, label: ['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN'][index], from, to: new Date(from.getTime() + 86400000) };
        });
    }
    const days = new Date(Date.UTC(year, month, 0)).getUTCDate();
    return Array.from({ length: day }, (_, index) => {
        const n = index + 1;
        const key = `${parts.year}-${parts.month}-${String(n).padStart(2, '0')}`;
        const from = new Date(Date.UTC(year, month - 1, n) - 7 * 3600000);
        return { key, label: n === 1 || n % 5 === 0 || n === days ? String(n) : '', from, to: new Date(from.getTime() + 86400000) };
    });
}

function overviewMatrix(range) {
    const now = overviewTimeline?.generated_at ? new Date(overviewTimeline.generated_at) : new Date();
    const columns = overviewColumns(range, now);
    const byKey = new Map();
    for (const bucket of overviewTimeline?.buckets || []) {
        const part = localParts(bucket.at);
        const key = range === 'day' ? `${part.year}-${part.month}-${part.day}T${part.hour}` : `${part.year}-${part.month}-${part.day}`;
        const totals = byKey.get(key) || {};
        totals.total = (totals.total || 0) + Number(bucket.total || 0);
        for (const [name, count] of Object.entries(bucket.severity || {})) totals[name] = (totals[name] || 0) + Number(count || 0);
        byKey.set(key, totals);
    }
    const matrix = overviewSeverityRows.map(row => ({ ...row, cells: columns.map(column => {
        const counts = byKey.get(column.key) || {};
        const count = row.codes.reduce((sum, key) => sum + Number(counts[key] || 0), 0);
        return { ...column, count };
    }) }));
    const total = columns.reduce((sum, column) => sum + (byKey.get(column.key)?.total || 0), 0);
    return { columns, matrix, total, now };
}

function demoOverviewTimeline() {
    const byHour = new Map();
    const categoryCounts = Object.fromEntries(overviewCategoryRows.map(([key]) => [key, 0]));
    const candidateByRule = new Map(demoLearning.map(item => [String(item.document.rule_id), item.document]));
    for (const row of demoLogs.filter(item => item.portal?.source_group === 'waf' && (item.portal?.blocked || item.portal?.category))) {
        const at = new Date(row['@timestamp']);
        const part = localParts(at);
        const key = `${part.year}-${part.month}-${part.day}T${part.hour}`;
        const ruleId = String(row.portal?.rules?.[0] || '');
        const source = candidateByRule.get(ruleId);
        const code = source?.severity_syslog == null ? NaN : Number(source.severity_syslog);
        const severity = demoSeverityKey(row, code);
        const category = row.portal?.category_key || 'unclassified';
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
        const bucket = byHour.get(key) || { at: at.toISOString(), total: 0, severity: {} };
        bucket.total++;
        bucket.severity[severity] = (bucket.severity[severity] || 0) + 1;
        byHour.set(key, bucket);
    }
    const seen = new Set();
    const alerts = demoLogs.filter(row => row.portal?.source_group === 'waf' && (row.portal?.blocked || row.portal?.category))
        .map(row => {
            const id = requestIdOf(row);
            if (!id || seen.has(id)) return null;
            seen.add(id);
            const rawSeverity = row.transaction?.messages?.[0]?.details?.severity ?? row.severity ?? 'unknown';
            return { request_id: id, at: row['@timestamp'], method: row.portal.method || '', path: row.portal.path || '',
                category: row.portal.category || 'WAF blocked request', severity: rawSeverity, rules: row.portal.rules || [],
                status: row.portal.status, blocked: Boolean(row.portal.blocked), source: row.portal.source_label || 'WAF',
                review: { status: 'pending', note: '', at: null } };
        }).filter(Boolean).slice(0, 50);
    return { generated_at: new Date().toISOString(), timezone: overviewZone, total: [...byHour.values()].reduce((sum, item) => sum + item.total, 0), category_counts: categoryCounts, buckets: [...byHour.values()], alerts };
}

function demoSeverityKey(row, sourceCode) {
    const raw = row.transaction?.messages?.[0]?.details?.severity;
    const code = Number.isInteger(sourceCode) ? sourceCode : /^\d$/.test(String(raw ?? '')) ? Number(raw) : undefined;
    if (Number.isInteger(code) && code >= 0 && code <= 7) return ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'][code];
    const named = String(raw ?? '').toLowerCase();
    if (['emergency', 'emerg', 'alert', 'critical', 'error', 'warning', 'warn', 'notice', 'info', 'debug'].includes(named)) return named === 'emerg' ? 'emergency' : named === 'warn' ? 'warning' : named;
    return 'unknown';
}

function overview() {
    const pending = learning.filter(x => ['candidate', 'needs_review'].includes(x.status)).length;
    const active = policy.tuning_rules.filter(r => r.enabled !== false && new Date(r.expires_at) > new Date()).length;
    const summary = overviewMatrix(overviewRange);
    const statsAvailable = Boolean(overviewTimeline) && overviewTimeline.stats_available !== false;
    const alertsAvailable = Boolean(overviewTimeline) && overviewTimeline.alerts_available !== false;
    const rangeLabels = { day: 'Trong ngày', week: 'Trong tuần', month: 'Trong tháng' };
    const heatmap = statsAvailable ? `<section class="panel heatmap-panel">
        <div class="panel-head"><div><h2>Log WAF đáng chú ý</h2><small>${fmt(summary.total)} bản ghi trong ${rangeLabels[overviewRange].toLowerCase()} · giờ Việt Nam · cập nhật ${esc(date(overviewTimeline.generated_at))}</small></div>
            <div class="range-switch" role="group" aria-label="Khoảng thời gian heatmap">${Object.entries(rangeLabels).map(([key, label]) => `<button type="button" data-action="overview-range" data-range="${key}" aria-pressed="${overviewRange === key}">${label}</button>`).join('')}</div>
        </div>
        <div class="heatmap-legend" aria-label="Chú giải mức độ">${overviewSeverityRows.map(row => `<span><i style="--legend-color:${row.color}"></i>${row.label}</span>`).join('')}</div>
        <div class="heatmap-scroll" tabindex="0" role="region" aria-label="Heatmap log WAF đáng chú ý theo thời gian và mức độ">
            <table class="heatmap"><thead><tr><th scope="col">Mức độ</th>${summary.columns.map(column => `<th scope="col">${esc(column.label)}</th>`).join('')}</tr></thead><tbody>${summary.matrix.map(row => `<tr><th scope="row"><span class="heatmap-severity" style="--severity-color:${row.color}">${row.label}</span></th>${row.cells.map(cell => {
                const strength = cell.count ? Math.max(20, Math.round(cell.count / Math.max(1, ...summary.matrix.flatMap(line => line.cells.map(item => item.count))) * 86)) : 0;
                return `<td><button type="button" class="heat-cell" data-action="overview-cell" data-severity="${row.key}" data-start="${cell.from.toISOString()}" data-end="${cell.to.toISOString()}" style="--heat-color:${row.color};--heat-strength:${strength}%" aria-label="${esc(`${cell.label || cell.from.toLocaleDateString('vi-VN')} · ${row.label}: ${cell.count} lượt ghi nhận`)}" title="${esc(`${cell.label || cell.from.toLocaleDateString('vi-VN')} · ${row.label}: ${cell.count}. Mở nhật ký đã lọc.`)}">${cell.count ? fmt(cell.count) : ''}</button></td>`;
            }).join('')}</tr>`).join('')}</tbody></table>
        </div>
        <div class="heatmap-footer"><span>${summary.total ? 'Chọn một ô để xem các log WAF trong khoảng đó.' : 'Chưa có log WAF đáng chú ý trong khoảng thời gian này.'}</span><span>Nguồn: Elasticsearch · Coraza / WAF policy</span></div>
    </section>` : `<section class="panel empty">${overviewLoading ? 'Đang tải thống kê log…' : 'Chưa tải được heatmap và phân loại log. Danh sách cần xử lý vẫn có thể sử dụng.'}</section>`;
    const categories = statsAvailable ? `<section class="panel categories-panel"><div class="panel-head"><div><h2>Phân loại sự kiện</h2><small>Bản ghi WAF đáng ngờ trong tháng · cùng bộ lọc với trang nhật ký</small></div></div><div class="category-grid">${overviewCategoryRows.map(([key, label]) => `<button type="button" data-action="overview-category" data-category="${key}" aria-label="Xem ${esc(label)} trong nhật ký tháng này"><strong>${fmt(overviewTimeline.category_counts?.[key] || 0)}</strong><span>${esc(label)}</span></button>`).join('')}</div></section>` : '';
    const alertRows = alertsAvailable ? (overviewTimeline.alerts || []).filter(item => !['resolved', 'false_positive'].includes(item.review?.status)) : [];
    const severityRank = value => {
        const raw = String(value ?? '').toLowerCase();
        if (['0', 'emergency', 'emerg', '1', 'alert'].includes(raw)) return 0;
        if (['2', 'critical', '3', 'error'].includes(raw)) return 1;
        if (['4', 'warning', 'warn'].includes(raw)) return 2;
        if (['5', 'notice', '6', 'info', 'informational', '7', 'debug'].includes(raw)) return 3;
        return 4;
    };
    const topAlerts = [...alertRows].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || Number(b.blocked) - Number(a.blocked) || Date.parse(b.at || 0) - Date.parse(a.at || 0)).slice(0, 5);
    const alertPriorities = topAlerts.filter(row => severityRank(row.severity) <= 1 || row.blocked).length;
    const priorities = `<section class="panel priority-panel"><div class="panel-head"><div><h2>Log cần xử lý</h2><small>${alertsAvailable ? `${alertRows.length} request chưa đóng trong mẫu gần nhất${alertPriorities ? ` · ${alertPriorities} ưu tiên cao` : ''} · tối đa 50 request trong tháng` : overviewLoading ? 'Đang tải danh sách log…' : 'Danh sách log hiện chưa khả dụng'}</small></div><a href="#logs">Mở nhật ký</a></div>
        ${topAlerts.length ? `<div class="priority-list">${topAlerts.map(row => {
            const rank = severityRank(row.severity);
            const urgency = rank === 0 ? 'Khẩn cấp' : rank === 1 ? 'Cao' : rank === 2 ? 'Cảnh báo' : rank === 3 ? 'Thông tin' : 'Chưa phân loại';
            const tone = rank === 0 || row.blocked ? 'urgent' : rank === 1 ? 'high' : '';
            const ruleLabel = row.rules?.length ? ` · rule ${row.rules.join(', ')}` : '';
            return `<article class="priority-item"><div class="priority-rank ${tone}">${esc(urgency)}${row.blocked ? ' · bị chặn' : ''}</div><div class="priority-copy"><strong>${esc(row.category)} · ${esc(row.method)} ${esc(row.path)}</strong><span>${esc(row.source)}${esc(ruleLabel)} · HTTP ${esc(row.status ?? '—')} · ${esc(date(row.at))} · ID ${esc(row.request_id)}</span></div><div class="priority-actions"><button class="small" data-action="open-alert-log" data-request-id="${esc(row.request_id)}">Điều tra</button><button class="small" data-action="review-alert" data-request-id="${esc(row.request_id)}">Xử lý</button></div></article>`;
        }).join('')}</div>` : `<div class="empty priority-empty">${alertsAvailable ? 'Không có request đáng ngờ nào đang chờ xử lý.' : overviewLoading ? 'Đang tải request đáng ngờ…' : 'Chưa tải được danh sách log; hãy làm mới để thử lại.'}</div>`}
        <div class="table-footer"><span>Trạng thái xử lý được lưu trong audit của portal; dấu hiệu WAF cần đối chiếu với request trace.</span><a href="#findings">${learningLoading ? 'Đang tải' : pending} ứng viên learning · mở hàng đợi</a></div></section>`;
    return `<div class="metrics">${[
    ['Chế độ thực thi',policy.mode==='On'?'Blocking':'Detection','Coraza & chính sách hành vi','◇'],
    ['Chờ xử lý trong mẫu',alertsAvailable ? fmt(alertRows.length) : '…',overviewLoading ? 'Đang tải request đáng ngờ' : alertsAvailable ? 'Tối đa 50 request nghi ngờ gần nhất' : 'Chưa có dữ liệu log','↗'],
    ['Ngoại lệ đang áp dụng',fmt(active),'Có phạm vi và thời hạn','≋'],
    ['Blocking / Detection PL',`${policy.blocking_pl}<em>/ ${policy.detection_pl}</em>`,'Paranoia level đã cấu hình','◈']
  ].map(([l,v,n,i])=>`<section class="metric"><div class="metric-label">${l}<span>${i}</span></div><div class="metric-value">${v}</div><div class="metric-note">${n}</div></section>`).join('')}</div>
  <div class="flow-strip"><span class="dot"></span><strong>Finance protection</strong><span>HAProxy</span><span>→</span><span>Coraza / CRS</span><span>→</span><span>Finance</span><span class="spacer"></span><span class="tag">CẤU HÌNH LAB</span><a href="http://127.0.0.1:5601" target="_blank" rel="noopener" aria-label="Mở Kibana để xem log WAF" title="Mở Kibana để xem log WAF">Mở Kibana ↗</a></div>
  ${heatmap}${categories}${priorities}`;
}

function policyView() {
    return `<div class="equal-col">${panel('Chế độ & paranoia level',toggle('enabled','Bật các policy tùy chỉnh của lab')+grid(choice('mode','Chế độ WAF',[['On','On · Cho phép chặn'],['DetectionOnly','DetectionOnly · Ghi nhận']])+choice('blocking_pl','Blocking PL',[1,2,3,4])+choice('detection_pl','Detection PL',[1,2,3,4]))+'<p class="subtle">Tắt policy tùy chỉnh không tắt CRS. DetectionOnly ghi nhận thay vì chặn.</p>')}${panel('Virtual patch & fixture',toggle('cve_rules.CVE-2026-64642','CVE-2026-64642 · Middleware bypass')+toggle('cve_rules.CVE-2026-64645','CVE-2026-64645 · Rewrite SSRF')+toggle('crs_exclusions.sqli_search','Ngoại lệ 942100 tại /api/lab/search')+'<p class="subtle">Virtual patch khớp route fixture của lab. Ngoại lệ SQLi có thể làm bỏ sót tấn công tại endpoint này.</p>')}</div>${tuningView()}`;
}

function botsView() {
    return `<div class="hint">Bot detection dùng User-Agent tự khai báo và hành vi. Rate limit chung vẫn áp dụng với client giả User-Agent trình duyệt. Chọn “Chặn” và WAF On để thực thi.</div><div class="equal-col">${panel('Nhận diện bot & chống spam',toggle('bot_detection.enabled','Bật bot detection')+grid(field('bot_detection.spam_requests','Sức chứa token bucket','number',{max:10000})+field('bot_detection.spam_window_seconds','Thời gian nạp đầy bucket (giây)','number',{max:3600})+field('bot_detection.unique_paths','Số đường dẫn khác nhau','number',{min:3,max:100})+field('bot_detection.window_seconds','Cửa sổ quét đường dẫn (giây)','number',{max:3600})+action('bot_detection.action'))+'<p class="subtle">Ví dụ 10 token / 10 giây: burst tối đa 10, nạp lại 1 token/giây. Bộ đếm nằm trong tiến trình WAF.</p>')}${panel('Giới hạn request theo IP / CIDR',toggle('rate_limit.enabled','Bật rate limit chung')+grid(field('rate_limit.requests','Request / IP')+field('rate_limit.window_seconds','Cửa sổ / IP (giây)')+field('rate_limit.range_requests','Request / CIDR')+field('rate_limit.range_window_seconds','Cửa sổ / CIDR (giây)')+choice('rate_limit.prefix_v4','Prefix IP v4',[32,24,16,8])+choice('rate_limit.prefix_v6','Prefix IP v6',[128,64,48])+choice('rate_limit.range_prefix_v4','Prefix CIDR v4',[24,16,8])+choice('rate_limit.range_prefix_v6','Prefix CIDR v6',[64,48])))}</div>${Object.entries({login_failures:'Đăng nhập thất bại',not_found_burst:'Quét URL · Burst 404',sequential_documents:'Truy cập chứng từ tuần tự'}).map(([k,l])=>panel(l,toggle(`behavior.${k}.enabled`,'Bật xử lý hành vi')+grid(field(`behavior.${k}.limit`,'Số lần ghi nhận','number',{max:10000})+field(`behavior.${k}.window_seconds`,'Cửa sổ (giây)','number',{max:3600})+action(`behavior.${k}.action`)))).join('')}`;
}

function accessView() {
    return `<div class="hint">Danh sách IP/CIDR được portal kiểm tra rồi sinh rule Coraza @ipMatch; denylist ưu tiên trước allowlist. IP được cho phép vẫn qua CRS. Log chặn ghi mã quốc gia từ fixture Docker hoặc GeoIP MMDB nếu có; khi không tra được sẽ là ZZ. Allowlist để trống sẽ không giới hạn theo danh sách cho phép.</div><div class="equal-col">${panel('IP / CIDR',toggle('ip_policy.enabled','Bật chính sách IP / CIDR')+grid(field('ip_policy.deny','Danh sách chặn','list',{wide:true,help:'Mỗi dòng một IP hoặc CIDR.'})+field('ip_policy.allow','Danh sách cho phép','list',{wide:true})))}${panel('Quốc gia / GeoIP',toggle('geo.enabled','Bật country policy')+grid(field('geo.deny','Mã quốc gia chặn','list',{help:'Mỗi dòng một mã, ví dụ US.'})+field('geo.allow','Mã quốc gia cho phép','list')+field('geo.fixtures','Ánh xạ IP → mã quốc gia','json',{wide:true,rows:5})))}</div>`;
}

function tuningView() {
    return `<div class="hint">Tuning rules tạo ngoại lệ CRS có phạm vi hẹp theo Host, rule, method, đường dẫn và tham số. Mọi thay đổi ở đây là bản nháp dùng chung với cấu hình WAF; nhấn “Lưu và áp dụng policy” để cập nhật. Ngoại lệ cần có lý do và thời hạn.</div><section class="panel"><div class="panel-head"><h2>Ngoại lệ CRS <span class="subtle">/ ${policy.tuning_rules.length}</span></h2><button class="primary" data-action="add-tuning">＋ Thêm ngoại lệ</button></div>${policy.tuning_rules.length?`<div class="table-wrap"><table><thead><tr><th>RULE / PHẠM VI</th><th>HOST / ROUTE</th><th>LÝ DO</th><th>HẾT HẠN</th><th>TRẠNG THÁI</th><th></th></tr></thead><tbody>${policy.tuning_rules.map((r,i)=>`<tr><td><strong>${r.rule_id}</strong><br><span class="mono">${esc(r.target||'Toàn rule trên route')}</span></td><td>${esc(r.host || (r.site === 'finance-patched' ? 'patched.localhost' : 'localhost'))}<br><span class="mono">${esc(r.method)} ${esc(r.path)}</span></td><td>${esc(r.reason)}</td><td>${esc(date(r.expires_at))}</td><td>${badge(r.enabled===false?'Tạm tắt':new Date(r.expires_at)<new Date()?'Hết hạn':'Đang bật',r.enabled===false?'gray':'')}</td><td><div class="action-row"><button class="small" data-action="edit-tuning" data-index="${i}">Sửa</button><button class="small danger" data-action="remove-tuning" data-index="${i}">Thu hồi</button></div></td></tr>`).join('')}</tbody></table></div>`:'<div class="empty">Chưa có ngoại lệ CRS.<br>Tạo ngoại lệ sau khi xác minh false positive.</div>'}</section>`;
}

function automationView() {
    return `<div class="equal-col">${panel('Learning worker',`<div class="status-line"><span>Heartbeat gần nhất</span><strong>${esc(date(health.worker_last_seen))}</strong></div><div class="status-line"><span>Trạng thái heartbeat</span>${badge(!health.worker_last_seen?'Chưa có':Date.now()-new Date(health.worker_last_seen)>120000?'Quá 2 phút':'Gần đây',!health.worker_last_seen?'gray':'')}</div><div class="status-line"><span>Ứng viên đã tải</span><strong>${learning.length}</strong></div><div class="status-line"><span>Đang theo dõi thay đổi</span><strong>${policy.automation.transition?'Có':'Không'}</strong></div><p class="subtle">Worker đọc Elasticsearch mỗi 60 giây. <a href="#findings">Mở hàng đợi để đánh nhãn →</a></p>`)}${panel('Chế độ automation',grid(choice('automation.mode','Chế độ',[['manual','Manual · Chỉ đề xuất'],['automatic','Automatic · Theo điều kiện']])+choice('automation.target_pl','PL mục tiêu',[1,2,3,4]))+toggle('automation.flow_test_passed','Xác nhận kiểm thử luồng hợp lệ đã đạt')+toggle('automation.auto_exceptions','Cho phép ngoại lệ tham số tự động')+field('automation.approved_paths','Endpoint cho phép ngoại lệ tự động','list',{help:'Một đường dẫn chính xác mỗi dòng.'}))}</div><div class="hint">Nâng PL yêu cầu 7 ngày và 10.000 request, cùng xác nhận kiểm thử và không có false positive nghiêm trọng chưa xử lý. Ngoại lệ tự động cần bằng chứng do admin xác nhận. Theo dõi 15 phút sau thay đổi để rollback. UI không tự kích hoạt nâng PL.</div>`;
}

function learningTable(rows, actions = true) {
    if (!rows.length) return '<div class="empty">Không có ứng viên phù hợp.<br>Dữ liệu xuất hiện khi learning worker thu thập được sự kiện.</div>';
    return `<div class="table-wrap"><table><thead><tr><th>RULE / ENDPOINT</th><th>LOẠI</th><th>REQUEST ĐÃ GOM</th><th>MỨC ĐỘ</th><th>TRẠNG THÁI</th><th>${actions?'THAO TÁC':'PL'}</th></tr></thead><tbody>${rows.map(r=>{const d=r.document;return `<tr><td><span class="route-title">CRS ${esc(d.rule_id)} · ${esc(d.method)}</span><span class="mono">${esc(d.path)}</span></td><td>${badge(d.parameter||'Rule match','purple')}</td><td>${fmt(d.count)} <span class="subtle">/ ${fmt(d.days)} ngày</span></td><td>${candidateSeverityBadge(d)}</td><td>${badge(r.status,r.status==='confirmed_fp'?'':'gray')}</td><td>${actions?`<button class="small" data-action="review" data-key="${esc(r.key)}">Đánh giá ↗</button>`:esc('PL '+d.pl)}</td></tr>`;}).join('')}</tbody></table></div>`;
}

function findings() {
    const all = learning.filter(r => (filter === 'all' || r.status === filter) && JSON.stringify(r).toLowerCase().includes(search.toLowerCase()));
    const pages = Math.max(1, Math.ceil(all.length / 10));
    page = Math.min(page, pages);
    return `<div class="toolbar"><input id="search" type="search" aria-label="Tìm ứng viên" placeholder="Tìm rule ID, endpoint, request ID…" value="${esc(search)}"><select id="filter" aria-label="Lọc trạng thái">${['all','candidate','needs_review','confirmed_fp','dismissed','auto_applied'].map(s=>`<option ${filter===s?'selected':''}>${s}</option>`).join('')}</select><button data-action="export">↓ Xuất JSON</button></div><section class="panel"><div class="panel-head"><h2>Ứng viên learning <span class="subtle">/ ${all.length}</span></h2><small>Dữ liệu hiện có · không phải luồng log trực tiếp</small></div>${learningTable(all.slice((page-1)*10,page*10))}<div class="table-footer"><span>${all.length} kết quả · Tối đa 200 ứng viên từ API</span><div class="action-row"><button data-action="prev" ${page===1?'disabled':''}>←</button><span>${page} / ${pages}</span><button data-action="next" ${page===pages?'disabled':''}>→</button></div></div></section>`;
}

function renderInvestigation(model, truncated = false) {
    const shown = (value, limit = 320) => {
        if (value === undefined || value === null || value === '') return 'Không có trong log';
        const clean = redactText(typeof value === 'object' ? JSON.stringify(redactLog(value)) : String(value));
        return esc(clean.length > limit ? clean.slice(0, limit) + ' [đã giới hạn ' + limit + ' ký tự]' : clean);
    };
    const item = (name, value, limit) => '<div class="trace-field"><dt>' + esc(name) + '</dt><dd>' + shown(value, limit) + '</dd></div>';
    const json = (value, limit = 32000) => {
        const clean = JSON.stringify(redactLog(value), null, 2) || '{}';
        return esc(clean.length > limit ? clean.slice(0, limit) + '\n[đã giới hạn ' + limit + ' ký tự]' : clean);
    };
    const decision = renderInvestigationDecisions(model.decisions);
    const headers = Object.entries(model.request.headers).map(([name, value]) =>
        '<div class="trace-field"><dt>' + esc(name) + '</dt><dd>' + shown(Array.isArray(value) ? value.join(', ') : value, 500) + '</dd></div>'
    ).join('') || '<p class="trace-muted">Không có header liên quan trong log.</p>';
    const body = model.bodyEvidence.length ? model.bodyEvidence.map(entry =>
        '<div class="trace-match">' + item('Rule ID', entry.rule_id) + item('Target body', entry.variable) + item('Đoạn khớp', entry.match, 700) +
        '<small>' + shown(entry.source) + '</small></div>'
    ).join('') : '<p class="trace-muted">Không có bằng chứng body trong log.</p>';
    const evidence = model.evidence.map(entry =>
        '<article class="trace-evidence"><div class="trace-evidence-head"><strong>' + shown(entry.source) + '</strong><time>' + shown(date(entry.at)) +
        '</time><span>' + shown(entry.match) + '</span></div><div class="trace-evidence-id">X-Request-ID: ' + shown(entry.id) +
        '</div><details><summary>JSON nguồn đã che dữ liệu nhạy cảm</summary><pre>' +
        json(Object.fromEntries(Object.entries(entry.row).filter(([name]) => name !== 'portal'))) + '</pre></details></article>'
    ).join('');
    const missing = model.missing.map(name => '<span>' + shown(name) + ': không tìm thấy</span>').join('');
    const route = model.route;
    const upstream = model.appSeen ? 'Có log Finance cùng X-Request-ID' :
        model.fallback ? 'HAProxy chọn backend dự phòng; chưa tìm thấy log Finance cùng ID' :
        model.corazaBlocked || model.policyBlocked ? 'WAF ghi chặn; không có bằng chứng upstream nhận request' :
        'Không xác định; chưa tìm thấy log Finance cùng ID';
    return '<div class="trace-layout">' +
        '<section class="trace-section"><h3>Kết quả</h3><strong class="trace-verdict">' + shown(model.title) + '</strong><dl class="trace-fields">' +
        item('HTTP status', model.status) + item('Nguồn tạo response', model.responseSource) +
        item('X-Request-ID', model.id, 240) + '</dl>' +
        (model.conflicting ? '<p class="trace-warning">Các nguồn đưa ra kết quả khác nhau. Xem timestamp và JSON từng bản ghi trước khi kết luận.</p>' : '') +
        (truncated ? '<p class="trace-warning">Truy vấn vượt 200 bản ghi. Kết luận có thể thiếu bằng chứng.</p>' : '') + '</section>' +
        '<section class="trace-section"><h3>Request</h3><dl class="trace-fields">' +
        item('Method', model.request.method) + item('Host', model.request.host) + item('Path / URI', model.request.path, 700) +
        item('IP nguồn', model.request.ip) + item('User-Agent', model.request.userAgent, 500) + '</dl>' +
        '<h4>Header liên quan</h4><dl class="trace-fields">' + headers + '</dl><h4>Body khớp rule</h4>' + body +
        '<details><summary>Mở full request đã che dữ liệu nhạy cảm</summary><pre>' + json(model.request.full, 16000) + '</pre></details></section>' +
        '<section class="trace-section"><h3>Quyết định</h3>' + decision + '</section>' +
        '<section class="trace-section"><h3>Tuyến và upstream</h3><dl class="trace-fields">' +
        item('Route', route.route) + item('Backend', route.backend) + item('Server', route.server) +
        item('WAF trên tuyến', model.fallback ? 'Không; HAProxy chọn server dự phòng' : model.bypass ? 'Không; tuyến bypass' :
            route.server === 'waf' ? 'Có; HAProxy chọn server waf' : null) +
        item('Upstream nhận request', upstream) + item('HTTP tại HAProxy', model.status) + '</dl></section>' +
        '<section class="trace-section"><h3>Bằng chứng thô</h3><p class="trace-muted">Bản ghi được đối chiếu bằng X-Request-ID chính xác; nguồn vắng mặt chỉ có nghĩa không tìm thấy trong kết quả truy vấn.</p>' +
        '<div class="trace-missing">' + missing + '</div>' + evidence + '</section>' +
        '<section class="trace-section"><h3>Cấu hình tại thời điểm request</h3><dl class="trace-fields">' +
        item('WAF mode', model.config.mode || 'Không xác minh được lịch sử') + item('Nguồn mode', model.config.modeSource) +
        item('Policy version', model.config.version) + item('Blocking PL', model.config.blockingPL) +
        item('Detection PL', model.config.detectionPL) + item('Nguồn PL', model.config.plSource) +
        item('Rule tính năng', model.config.featureRule) +
        item('Tính năng bật', model.config.featureEnabled === null ? null : model.config.featureEnabled ? 'Có' : 'Không') +
        item('Action cấu hình', model.config.featureAction) + item('Nguồn action', model.config.featureSource) +
        '</dl><p class="trace-muted">Cấu hình hiện tại của portal không được gán cho request cũ.</p></section>' +
        '</div>';
}

function logRows() {
    if (logsLoading) return '<section class="panel empty">Đang tải nhật ký…</section>';
    if (logsError) return `<section class="panel empty">Không tải được nhật ký: ${esc(logsError)}</section>`;
    if (!logs.length) return '<section class="panel empty">Không có sự kiện phù hợp trong khoảng thời gian đã chọn. Thử mở rộng thời gian hoặc tạo request mới.</section>';
    const requests = new Map();
    const entries = [];
    let systemCount = 0;
    for (const row of logs) {
        const id = requestIdOf(row) || row.portal?.correlation?.haproxy?.request_id || '';
        if (!id) {
            entries.push({ row });
            systemCount++;
            continue;
        }
        if (!requests.has(id)) {
            const rows = [];
            requests.set(id, rows);
            entries.push({ id, rows });
        }
        requests.get(id).push(row);
    }
    const sourceName = row => row.portal?.source_label || row.event?.dataset || 'Nguồn khác';
    const safeText = value => esc(String(value ?? '')
        .replace(/([?&](?:access[_-]?token|refresh[_-]?token|token|api[_-]?key|password|passwd|pwd|secret|session)=)[^&\s]+/ig, '$1[đã che]')
        .replace(/\bbearer\s+[A-Za-z0-9._~+/-]+=*/ig, 'Bearer [đã che]')
        .replace(/(authorization|cookie|set-cookie|access[_-]?token|refresh[_-]?token|api[_-]?key|token|password|passwd|pwd|secret|session)\s*[:=]\s*[^\s,;]+/ig, '$1: [đã che]')
        .slice(0, 240));
    const body = entries.map(entry => {
        if (entry.row) {
            const row = entry.row;
            const source = sourceName(row);
            const status = row.portal?.status;
            const category = row.portal?.category || (row.portal?.category_key === 'other' ? 'Khác · sự kiện hệ thống' : 'Chưa phân loại');
            const eventTitle = /^WAF (?:down|up)$/.test(row.portal?.explanation || '') || row.event?.action === 'waf_config_reconciled' ? row.portal.explanation : row.event?.action || row.portal?.explanation || source;
            const eventResult = status == null ? 'Đã ghi nhận' : Number(status) >= 400 ? `HTTP ${esc(status)} · Chưa rõ nguồn từ chối` : `HTTP ${esc(status)}`;
            return `<tr class="system-summary"><td>${esc(date(row['@timestamp']))}</td><td>${safeText(row.portal?.ip || 'Chưa rõ IP')}</td><td><strong class="request-path">${safeText(eventTitle)}</strong><span class="mono request-id">Không có X-Request-ID</span></td><td>${esc(category)}</td><td><span class="request-result ${status != null && Number(status) >= 400 ? 'rejected' : 'unknown'}">${eventResult}</span></td><td><span class="subtle">Không áp dụng</span></td><td><div class="request-source-list"><span>${esc(source)}</span></div></td></tr>`;
        }
        const { id, rows } = entry;
        const primary = rows[0];
        const proxy = rows.find(row => row.portal?.source_group === 'haproxy');
        const context = rows.find(row => row.portal?.correlation?.haproxy)?.portal.correlation.haproxy;
        const routeEvidence = context || proxy?.lab || {};
        const failover = routeEvidence.backend === 'finance_waf_with_fallback' && routeEvidence.server === 'finance-fallback';
        const bypass = routeEvidence.route === 'bypass' || routeEvidence.backend === 'finance_direct' || failover;
        const wafRouted = !bypass && (rows.some(row => row.portal?.source_group === 'waf') || routeEvidence.route === 'waf' || ['finance_waf_with_fallback','finance_patched_waf'].includes(routeEvidence.backend));
        const modeRow = rows.find(row => row.portal?.source_group === 'waf' && row.portal?.waf_mode) || rows.find(row => row.portal?.waf_mode);
        const modeLabel = modeRow?.portal?.waf_mode || 'Không xác định';
        const modeSourceLabel = modeRow?.portal?.waf_mode_source || modeRow?.portal?.source_label || 'chưa có bằng chứng';
        const wafBackends = ['finance_waf_with_fallback', 'finance_patched_waf'];
        const wafHealth = failover ? 'Down' : wafBackends.includes(routeEvidence.backend) && routeEvidence.server === 'waf' ? 'Healthy' : 'Không xác định';
        const wafHealthSource = failover ? 'HAProxy chọn finance-fallback' : wafBackends.includes(routeEvidence.backend) && routeEvidence.server === 'waf' ? `HAProxy chọn ${routeEvidence.backend}/${routeEvidence.server}` : 'thiếu bằng chứng backend/server';
        const corazaAuditRows = rows.filter(row => row.portal?.source_label === 'Coraza audit');
        const interruptedValues = [...new Set(corazaAuditRows
            .map(row => row.transaction?.is_interrupted ?? row.is_interrupted)
            .filter(value => typeof value === 'boolean'))];
        const interruptionLabel = interruptedValues.length > 1 ? 'is_interrupted không thống nhất'
            : interruptedValues[0] === true ? 'is_interrupted=true · giao dịch bị ngắt'
            : interruptedValues[0] === false ? 'is_interrupted=false · giao dịch không bị ngắt'
            : corazaAuditRows.length ? 'is_interrupted không có trong audit'
            : 'Không có Coraza audit trong dữ liệu đã tải';
        const info = primary.portal || {};
        const categoriesSeen = [...new Set(rows.map(row => row.portal?.category_key === 'other'
            ? `Khác${row.portal?.category ? ` · ${row.portal.category}` : ''}`
            : row.portal?.category).filter(Boolean))];
        const categoryLabel = categoriesSeen.length > 1 ? `Kết luận khác nhau: ${categoriesSeen.join(' / ')}` : categoriesSeen[0] || 'Chưa phân loại';
        const path = context?.path || rows.map(row => row.portal?.path).find(Boolean) || '';
        const method = context?.method || proxy?.http?.request?.method || primary.transaction?.request?.method || '';
        const ip = context?.client_ip || proxy?.portal?.ip || info.ip || '';
        const status = context?.status ?? rows.map(row => row.portal?.status).find(value => value != null);
        const decision = rows.map(row => row.portal?.correlation?.decision).find(Boolean);
        const corazaBlocked = rows.some(row => row.portal?.block_source === 'coraza') || decision?.source === 'coraza';
        const policyBlocked = rows.some(row => row.portal?.block_source === 'waf_policy') || decision?.source === 'waf_policy';
        const applicationLogged = rows.some(row => row.portal?.source_group === 'finance');
        const applicationRejected = rows.some(row => row.portal?.source_group === 'finance' &&
            (row.event?.outcome === 'application_rejected' || Number(row.portal?.status) >= 400)) || decision?.source === 'application';
        const corazaObserved = rows.some(row => row.portal?.source_label === 'Coraza audit' && row.portal?.rules?.length && !row.portal?.blocked);
        const policyEvents = rows.filter(row => row.event?.dataset === 'waf.behavior' && row.event?.kind === 'behavior');
        const policyRecord = rows.find(row => row.event?.dataset === 'waf.behavior' && row.portal?.policy_evidence);
        const policyEvidence = policyRecord?.portal?.policy_evidence;
        const policyObserved = policyEvents.some(row => row.event?.action === 'observe');
        const policyThreshold = policyEvents.some(row => row.event?.action === 'block');
        const blocked = corazaBlocked || policyBlocked;
        const conflictingOutcome = (corazaBlocked && policyBlocked) || (blocked && applicationRejected) || (blocked && context?.status === 404);
        const proxyUpstreamError = Number(status) >= 500 && !blocked && !applicationLogged;
        const resultClass = conflictingOutcome || (!blocked && Number(status) >= 400 && !proxyUpstreamError) ? 'rejected' : blocked ? 'blocked' : status == null || proxyUpstreamError ? 'unknown' : 'allowed';
        const resultText = conflictingOutcome ? (blocked && context?.status === 404 ? 'WAF ghi block, HAProxy trả HTTP 404' : 'Kết quả xử lý không thống nhất trong log')
            : corazaBlocked ? `Coraza chặn · ${status ?? 'chưa rõ HTTP'}`
            : policyBlocked ? `WAF policy chặn · ${status ?? 'chưa rõ HTTP'}`
            : policyThreshold && applicationRejected ? `Policy ghi ngưỡng; ứng dụng trả HTTP ${status}`
            : policyThreshold ? `Policy ghi nhận ngưỡng · request này nhận HTTP ${status ?? 'chưa rõ'}`
            : policyObserved && applicationRejected ? `Policy observe; ứng dụng trả HTTP ${status}`
            : policyObserved ? `Policy observe · request không bị policy ngắt · HTTP ${status ?? 'chưa rõ'}`
            : corazaObserved && applicationRejected ? `Coraza có rule match nhưng không ngắt · ứng dụng trả HTTP ${status}`
            : corazaObserved ? `Coraza có rule match, không có bằng chứng ngắt · HTTP ${status ?? 'chưa rõ'}`
            : applicationRejected ? `Ứng dụng trả HTTP ${status}`
            : Number(status) >= 500 ? `HTTP ${status} · lỗi proxy/upstream, chưa đủ log để tách nguồn`
            : rows.some(row => row.portal?.category_key === 'scanner') ? `Scanner được nhận diện · chưa có bằng chứng chặn · HTTP ${status ?? 'chưa rõ'}`
            : status === 403 ? '403 · Chưa rõ nguồn chặn'
            : Number(status) >= 400 ? `HTTP ${status} · Chưa rõ nguồn từ chối`
            : status == null ? 'Chưa đủ bằng chứng kết quả' : `HTTP ${status}`;
        const sourceLabels = [...new Set(rows.map(sourceName))];
        const counterNames = { requests_per_ip: 'request theo IP', requests_per_cidr: 'request theo CIDR', responses_404: 'HTTP 404', failed_logins: 'đăng nhập thất bại', sequential_document_ids: 'ID chứng từ liên tiếp', distinct_paths: 'đường dẫn khác nhau' };
        const counterLabel = policyEvidence?.counter_type === 'token_bucket'
            ? `token bucket: còn ${safeText(policyEvidence.tokens_remaining ?? '?')}/${safeText(policyEvidence.bucket_capacity ?? '?')} token · nạp theo ${safeText(policyEvidence.window_seconds ?? '?')} giây`
            : policyEvidence && Number.isFinite(Number(policyEvidence.count)) && Number.isFinite(Number(policyEvidence.limit))
                ? `${safeText(counterNames[policyEvidence.counter_type] || policyEvidence.counter_type || 'số lần')}: ${safeText(policyEvidence.count)}/${safeText(policyEvidence.limit)} trong ${safeText(policyEvidence.window_seconds ?? '?')} giây`
                : '';
        const decisionLabel = policyEvidence?.decision_result === 'blocked' ? 'Request này bị policy chặn thật'
            : policyEvidence?.decision_result === 'threshold_reached' ? 'Đã đạt ngưỡng; event này tự nó chưa chứng minh request bị chặn'
            : policyEvidence?.decision_result === 'threshold_observed' ? 'Đã đạt ngưỡng ở chế độ quan sát'
            : '';
        if (context && !sourceLabels.some(label => label.toLowerCase().includes('haproxy'))) sourceLabels.unshift('HAProxy · ngữ cảnh');
        if (decision?.source === 'coraza' && !sourceLabels.some(label => label.includes('Coraza'))) sourceLabels.push('Coraza · ngữ cảnh');
        if (decision?.source === 'waf_policy' && !sourceLabels.some(label => label.includes('WAF policy'))) sourceLabels.push('WAF policy · ngữ cảnh');
        const attention = blocked || rows.some(row => ['cve', 'sqli', 'xss', 'rce', 'lfi', 'ssrf', 'bot', 'rate_limit', 'scanner', 'behavior'].includes(row.portal?.category_key));
        const reviewStatus = logReviews[id]?.status || 'pending';
        const reviewLabel = ({ resolved: 'Đã xử lý', false_positive: 'Không đáng ngờ', needs_review: 'Chờ xử lý' })[reviewStatus] || (attention ? 'Chưa xử lý' : 'Chưa gắn cờ');
        const reviewCell = `<span class="review-state ${esc(reviewStatus)}">${esc(reviewLabel)}</span>${logReviews[id]?.at ? `<small class="review-time">${esc(date(logReviews[id].at))}</small>` : ''}<button class="small review-open" type="button" data-action="review-log" data-request-id="${esc(id)}">${logReviews[id] ? 'Cập nhật' : 'Đánh giá'}</button>`;
        const cachedTrace = traceCache.get(id);
        const traceRow = `<tr class="trace-row"><td colspan="7"><details data-trace-id="${esc(id)}" data-log-key="${esc(id)}"><summary>Điều tra request theo X-Request-ID</summary><div class="trace-content">${cachedTrace ? renderInvestigation(cachedTrace.model, cachedTrace.truncated) : '<p class="trace-muted">Mở để tra cứu toàn bộ bản ghi cùng X-Request-ID.</p>'}</div></details></td></tr>`;
        return `<tr class="request-summary"><td>${esc(date(primary['@timestamp']))}</td><td><strong>${safeText(ip || 'Chưa rõ IP')}</strong></td><td><strong class="request-path">${safeText(`${method} ${path}`.trim() || 'Chưa rõ đường dẫn')}</strong><span class="mono request-id">${safeText(id)}</span><button class="trace-open small" type="button" data-open-trace="${esc(id)}" aria-expanded="false">Điều tra</button>${wafRouted || failover ? `<span class="request-mode">Trạng thái WAF: <strong class="${wafHealth === 'Healthy' ? 'health-up' : wafHealth === 'Down' ? 'health-down' : ''}">${safeText(wafHealth)}</strong><small>Nguồn: ${safeText(wafHealthSource)}</small></span>` : ''}${wafRouted ? `<span class="request-mode">Mode WAF: <strong>${safeText(modeLabel)}</strong><small>Nguồn: ${safeText(modeSourceLabel)}</small></span>` : ''}<span class="request-mode coraza-outcome">Kết quả Coraza: <strong>${safeText(interruptionLabel)}</strong><small>is_interrupted là kết quả giao dịch, không xác định mode WAF</small></span>${counterLabel ? `<span class="request-mode"><strong>${counterLabel}</strong><small>${safeText(decisionLabel)}${policyEvidence.configured_action ? ` · action cấu hình: ${safeText(policyEvidence.configured_action)}` : ''}</small></span>` : ''}</td><td>${esc(categoryLabel)}${info.rules?.length ? `<span class="request-rule">Rule ${safeText(info.rules.join(', '))}</span>` : decision?.rule_id ? `<span class="request-rule">Rule ${safeText(decision.rule_id)}</span>` : ''}${policyEvidence?.effective_action ? `<span class="request-rule">Policy: ${safeText(policyEvidence.effective_action)} · ${safeText(policyEvidence.decision_result || 'chưa rõ')}</span>` : ''}</td><td><span class="request-result ${resultClass}">${esc(resultText)}</span></td><td>${reviewCell}</td><td><div class="request-source-list">${sourceLabels.map(label => `<span>${esc(label)}</span>`).join('')}<span>${rows.length} bản ghi ghép</span></div></td></tr>` + traceRow;
    }).join('');
    return `<section class="panel logs-panel"><div class="panel-head"><h2>Nhật ký <span class="subtle">/ ${requests.size} request · ${systemCount} sự kiện hệ thống</span></h2><small>${fmt(logsMeta.total)} bản ghi nguồn · trang ${logsMeta.page}/${logsMeta.pages}</small></div><div class="logs-table-frame"><div class="table-wrap logs-table-wrap" tabindex="0" role="region" aria-label="Bảng nhật ký cuộn ngang"><table class="logs-table request-table"><thead><tr><th>THỜI GIAN</th><th>IP CLIENT</th><th>REQUEST / SỰ KIỆN</th><th>LOẠI SỰ KIỆN</th><th>KẾT QUẢ</th><th>TRẠNG THÁI XỬ LÝ</th><th>NGUỒN ĐÃ THẤY</th></tr></thead><tbody>${body}</tbody></table></div></div><div class="table-footer"><span>Request cùng X-Request-ID được gom trong trang; sự kiện hệ thống hiển thị theo thời gian</span><div class="action-row"><button data-action="log-prev" ${logsMeta.page <= 1 ? 'disabled' : ''}>← Trước</button><button data-action="log-next" ${!logsMeta.next_after ? 'disabled' : ''}>Sau →</button></div></div></section>`;
}

function logsView() {
    const sources = [['all','Tất cả nguồn'],['haproxy','HAProxy'],['waf','WAF / Coraza'],['finance','Finance'],['portal','Portal'],['other','Khác / chưa phân loại']];
    const categories = [['all','Mọi loại'],['sqli','SQLi'],['xss','XSS'],['rce','Command Injection / RCE'],['lfi','Path Traversal / LFI'],['ssrf','SSRF'],['cve','CVE'],['bot','Bot Detection'],['scanner','Scanner Detection'],['behavior','Behavior'],['rate_limit','Rate Limit'],['other','Khác'],['unclassified','Chưa phân loại']];
    const severities = [['all','Mọi mức độ'],['alert','Khẩn cấp / cảnh báo'],['high','Nghiêm trọng / lỗi'],['warning','Cảnh báo'],['informational','Thông tin'],['unknown','Chưa phân loại']];
    const statuses = [['all','Mọi HTTP'],['2xx','2xx'],['3xx','3xx'],['4xx','4xx'],['5xx','5xx'],['403','403']];
    return `<div class="toolbar logs-toolbar"><input id="log-search" type="search" aria-label="Tìm trong nhật ký" placeholder="Tìm request ID, IP, rule, đường dẫn…" value="${esc(logQuery)}"><label>Từ <input id="log-from" type="datetime-local" step="60" value="${esc(logFrom)}" aria-label="Từ ngày giờ phút, giờ Việt Nam"></label><label>Trước <input id="log-to" type="datetime-local" step="60" value="${esc(logTo)}" aria-label="Trước ngày giờ phút, giờ Việt Nam"></label></div>${logSignal ? '<div class="hint">Đang lọc log WAF đáng chú ý như trên Tổng quan. <button type="button" class="small" data-action="clear-log-signal">Xem tất cả log</button></div>' : ''}<div class="logs-column-filters" aria-label="Lọc theo cột"><label>Nguồn<select id="log-dataset" aria-label="Lọc nguồn nhật ký">${sources.map(([value,label]) => `<option value="${value}" ${logDataset===value?'selected':''}>${label}</option>`).join('')}</select></label><label>Sự kiện<input id="log-event" type="search" placeholder="Tên sự kiện" value="${esc(logEvent)}"></label><label>Loại sự kiện<select id="log-category">${categories.map(([value,label]) => `<option value="${value}" ${logCategory===value?'selected':''}>${label}</option>`).join('')}</select></label><label>Mức độ<select id="log-severity">${severities.map(([value,label]) => `<option value="${value}" ${logSeverity===value?'selected':''}>${label}</option>`).join('')}</select></label><label>Đường dẫn<input id="log-path" type="search" placeholder="/api/..." value="${esc(logPath)}"></label><label>IP<input id="log-ip" type="search" placeholder="IP chính xác" value="${esc(logIp)}"></label><label>HTTP<select id="log-status">${statuses.map(([value,label]) => `<option value="${value}" ${logStatus===value?'selected':''}>${label}</option>`).join('')}</select></label></div><div id="logs-results">${logRows()}</div>`;
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
        host: 'localhost',
        rule_id: '',
        method: 'POST',
        path: '/api/transactions/reconcile/search',
        scope: 'target',
        target: 'ARGS:expression',
        reason: '',
        enabled: true,
        expires_at: new Date(Date.now() + 86400000).toISOString()
    };
    const input = (name, label, type = 'text', value = r[name]) => `<label class="field">${label}<input name="${name}" type="${type}" value="${esc(value)}" required></label>`;
    const select = (name, label, values, selected = r[name]) => `<label class="field">${label}<select name="${name}">${values.map(v=>`<option value="${esc(v)}" ${selected===v?'selected':''}>${v}</option>`).join('')}</select></label>`;
    const expiry = new Date(r.expires_at);
    const local = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
    dialog(existing ? 'Sửa ngoại lệ CRS' : 'Thêm ngoại lệ CRS', grid(select('host', 'Host chính xác', ['localhost', 'localhost:8080', 'patched.localhost', 'patched.localhost:8080', 'direct.localhost', 'direct.localhost:8080'], r.host || (r.site === 'finance-patched' ? 'patched.localhost' : 'localhost')) + input('rule_id', 'CRS rule ID', 'number') + select('method', 'Method', ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) + input('path', 'Đường dẫn chính xác') + select('scope', 'Phạm vi', ['target', 'rule']) + `<label class="field">Tham số CRS<input name="target" value="${esc(r.target)}"><small>Ví dụ ARGS:expression. Phạm vi rule bỏ qua trường này.</small></label>` + input('expires_at', 'Hết hạn', 'datetime-local', local) + `<label class="switch-field">Bật ngoại lệ<input name="enabled" type="checkbox" ${r.enabled!==false?'checked':''}></label>` + `<label class="field wide">Lý do và bằng chứng<textarea name="reason" required minlength="5" maxlength="200">${esc(r.reason)}</textarea></label>`), async f => {
        const expires = new Date(f.get('expires_at'));
        if (expires <= new Date() || expires > Date.now() + 30 * 86400000) throw new Error('Thời hạn phải ở tương lai và trong 30 ngày.');
        const next = {
            ...r,
            id: r.id || crypto.randomUUID(),
            rule_id: Number(f.get('rule_id')),
            host: f.get('host'),
            site: String(f.get('host')).startsWith('patched.') ? 'finance-patched' : 'finance-vulnerable',
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

function reviewAlert(requestId) {
    const overviewRow = (overviewTimeline?.alerts || []).find(item => item.request_id === requestId);
    const matchingLogs = logs.filter(item => requestIdOf(item) === requestId);
    const source = matchingLogs.find(item => item.portal?.source_group === 'waf' && (item.portal?.category || item.portal?.blocked)) || matchingLogs[0];
    const row = overviewRow || (source && { request_id: requestId, at: source['@timestamp'], method: source.portal?.method || '',
        path: source.portal?.path || '', category: source.portal?.category || 'Request trong nhật ký',
        rules: source.portal?.rules || [], status: source.portal?.status });
    if (!row) return;
    const previous = logReviews[requestId] || overviewRow?.review || {};
    const options = [['resolved', 'Đã xử lý'], ['false_positive', 'Đánh dấu không đáng ngờ'], ['needs_review', 'Giữ chờ xử lý']];
    dialog('Đánh giá request', `<p class="evidence">${esc(row.method)} ${esc(row.path)} · ${esc(row.category)}<br>Request ID: ${esc(row.request_id)}<br>Thời gian: ${esc(date(row.at))} · HTTP ${esc(row.status ?? '—')}<br>Rule: ${esc((row.rules || []).join(', ') || 'không có trong bản ghi')}</p><div class="hint">Ghi nhận quyết định xử lý theo request ID. Nội dung request không được sao chép vào audit.</div><label class="field">Kết quả<select name="status">${options.map(([value, label]) => `<option value="${value}" ${previous.status === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label><label class="field">Ghi chú<textarea name="note" rows="3" minlength="3" maxlength="500" required placeholder="Tóm tắt kiểm tra hoặc bước tiếp theo">${esc(previous.note || '')}</textarea></label>`, async form => {
        const status = String(form.get('status'));
        const note = String(form.get('note') || '').trim();
        if (note.length < 3) throw new Error('Ghi chú cần ít nhất 3 ký tự.');
        let review;
        if (preview) review = { status, note, at: new Date().toISOString() };
        else review = (await api('/api/log-reviews', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request_id: requestId, status, note }) })).review;
        if (overviewRow) overviewRow.review = review;
        logReviews[requestId] = review;
        let refreshFailed = false;
        if (!preview && currentRoute() === 'overview') {
            try { overviewTimeline = await api('/api/overview/logs'); }
            catch { refreshFailed = true; }
        }
        render();
        if (refreshFailed) notify('Đã lưu kết quả vào audit; chưa làm mới được danh sách log.', true);
        else notify(status === 'resolved' ? 'Đã ghi nhận xử lý request.' : status === 'false_positive' ? 'Đã ghi nhận đánh giá không đáng ngờ.' : 'Request được giữ trong danh sách chờ xử lý.');
    });
}
$('#content').addEventListener('toggle', async event => {
    const details = event.target;
    if (!(details instanceof HTMLDetailsElement) || !details.dataset.traceId) return;
    const opener = [...$('#content').querySelectorAll('button[data-open-trace]')]
        .find(button => button.dataset.openTrace === details.dataset.traceId);
    if (opener) opener.setAttribute('aria-expanded', String(details.open));
    if (!details.open) return;
    const id = details.dataset.traceId;
    const content = details.querySelector('.trace-content');
    if (!content) return;
    if (traceCache.has(id)) {
        const cached = traceCache.get(id);
        content.innerHTML = renderInvestigation(cached.model, cached.truncated);
        return;
    }
    content.innerHTML = '<p class="trace-muted">Đang tra cứu các nguồn log cùng X-Request-ID…</p>';
    try {
        if (!tracePending.has(id)) tracePending.set(id, preview
            ? Promise.resolve({ items: logs.filter(row => requestIdOf(row) === id), truncated: false })
            : api('/api/logs/trace?request_id=' + encodeURIComponent(id)));
        const data = await tracePending.get(id);
        const value = { model: investigateRequest(data.items || [], id), truncated: Boolean(data.truncated) };
        traceCache.set(id, value);
        if (details.isConnected && details.open) content.innerHTML = renderInvestigation(value.model, value.truncated);
    } catch (error) {
        if (details.isConnected) content.textContent = 'Không tải được diễn biến request: ' + error.message;
    } finally {
        tracePending.delete(id);
    }
}, true);
$('#content').addEventListener('click', event => {
    const button = event.target.closest('button[data-open-trace]');
    if (!button) return;
    const details = [...$('#content').querySelectorAll('details[data-trace-id]')]
        .find(entry => entry.dataset.traceId === button.dataset.openTrace);
    if (details) {
        details.open = !details.open;
        if (details.open) details.scrollIntoView({ block: 'nearest' });
    }
});
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
    if (t.id === 'log-dataset' || t.id === 'log-category' || t.id === 'log-severity' || t.id === 'log-status') {
        clearTimeout(logSearchTimer);
        if (t.id === 'log-dataset') logDataset = t.value;
        if (t.id === 'log-category') logCategory = t.value;
        if (t.id === 'log-severity') logSeverity = t.value;
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
$('#content').addEventListener('click', e => {
    const b = e.target.closest('[data-action]');
    if (!b) return;
    switch (b.dataset.action) {
        case 'overview-range':
            overviewRange = ['day', 'week', 'month'].includes(b.dataset.range) ? b.dataset.range : 'day';
            render();
            break;
        case 'overview-cell':
            logDataset = 'waf';
            logSignal = true;
            logCategory = 'all';
            logSeverity = b.dataset.severity || 'all';
            logStatus = 'all';
            logQuery = '';
            logFrom = localDatetime(b.dataset.start);
            logTo = localDatetime(b.dataset.end);
            resetLogPaging();
            location.hash = '#logs';
            break;
        case 'overview-category': {
            const category = b.dataset.category || 'all';
            if (!overviewCategoryRows.some(([key]) => key === category)) break;
            const parts = localParts(overviewTimeline?.generated_at || new Date());
            logDataset = 'waf';
            logSignal = true;
            logCategory = category;
            logSeverity = 'all';
            logStatus = 'all';
            logQuery = '';
            logFrom = `${parts.year}-${parts.month}-01T00:00`;
            logTo = localDatetime(new Date(Date.UTC(Number(parts.year), Number(parts.month), 1) - 7 * 3600000));
            resetLogPaging();
            location.hash = '#logs';
            break;
        }
        case 'open-finding-log':
            logDataset = 'all';
            logSignal = false;
            logCategory = 'all';
            logSeverity = 'all';
            logStatus = 'all';
            logQuery = b.dataset.requestId || '';
            logFrom = '';
            logTo = '';
            resetLogPaging();
            location.hash = '#logs';
            break;
        case 'open-alert-log':
            logDataset = 'all';
            logSignal = false;
            logCategory = 'all';
            logSeverity = 'all';
            logStatus = 'all';
            logQuery = b.dataset.requestId || '';
            logFrom = '';
            logTo = '';
            resetLogPaging();
            location.hash = '#logs';
            break;
        case 'clear-log-signal':
            logSignal = false;
            resetLogPaging();
            void loadLogs();
            break;
        case 'review-alert':
        case 'review-log':
            reviewAlert(b.dataset.requestId || '');
            break;
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
function pollLatestLogs() {
    if (currentRoute() !== 'logs' || document.hidden || preview || logsLoading || logPage !== 1) return;
    if (logTo && Date.parse(`${logTo}:00+07:00`) <= Date.now()) return;
    resetLogPaging();
    void loadLogs({ quiet: true });
}
setInterval(pollLatestLogs, 15000);
function refreshOverviewIfStale() {
    if (preview || currentRoute() !== 'overview' || document.hidden || overviewLoading) return;
    if (!overviewTimeline?.generated_at || Date.now() - Date.parse(overviewTimeline.generated_at) >= 60000) void loadOverview();
}
setInterval(refreshOverviewIfStale, 60000);
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        pollLatestLogs();
        refreshOverviewIfStale();
    }
});
window.addEventListener('hashchange', () => {
    document.body.classList.remove('menu-open');
    render();
    if (currentRoute() === 'logs') { resetLogPaging(); void loadLogs(); }
    refreshOverviewIfStale();
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
