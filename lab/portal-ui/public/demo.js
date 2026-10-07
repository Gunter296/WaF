export const demoPolicy = {
    "version": 0,
    "enabled": true,
    "mode": "On",
    "blocking_pl": 1,
    "detection_pl": 2,
    "cve_rules": {
        "CVE-2026-64642": false,
        "CVE-2026-64645": false
    },
    "crs_exclusions": {
        "sqli_search": false
    },
    "tuning_rules": [],
    "automation": {
        "mode": "manual",
        "target_pl": 2,
        "flow_test_passed": false,
        "auto_exceptions": false,
        "approved_paths": [],
        "last_change_at": null,
        "transition": null
    },
    "rate_limit": {
        "enabled": true,
        "requests": 30,
        "window_seconds": 10,
        "range_requests": 120,
        "range_window_seconds": 10,
        "prefix_v4": 32,
        "prefix_v6": 128,
        "range_prefix_v4": 24,
        "range_prefix_v6": 64
    },
    "geo": {
        "enabled": false,
        "deny": [],
        "allow": [],
        "fixtures": {
            "172.30.0.10": "VN",
            "172.30.0.20": "US"
        }
    },
    "ip_policy": {
        "enabled": false,
        "deny": [],
        "allow": []
    },
    "bot_detection": {
        "enabled": true,
        "unique_paths": 8,
        "window_seconds": 30,
        "spam_requests": 10,
        "spam_window_seconds": 10,
        "action": "observe"
    },
    "behavior": {
        "login_failures": {
            "enabled": true,
            "limit": 5,
            "window_seconds": 60,
            "action": "block"
        },
        "not_found_burst": {
            "enabled": true,
            "limit": 15,
            "window_seconds": 30,
            "action": "observe"
        },
        "sequential_documents": {
            "enabled": true,
            "limit": 4,
            "window_seconds": 30,
            "action": "observe"
        }
    }
};

// Preview fixtures only. Never sent to the live API.
const now = Date.now();
demoPolicy.version = 12;
demoPolicy.tuning_rules = [{
        id: '00000000-0000-4000-8000-000000000001',
        rule_id: 942100,
        site: 'finance-vulnerable',
        method: 'GET',
        path: '/api/lab/search',
        scope: 'target',
        target: 'ARGS:q',
        reason: 'Mẫu xem thử: tìm kiếm hợp lệ',
        expires_at: new Date(now + 86400000).toISOString(),
        enabled: true,
        source: 'manual'
    },
    {
        id: '00000000-0000-4000-8000-000000000002',
        rule_id: 941100,
        site: 'finance-patched',
        method: 'POST',
        path: '/api/lab/transfer',
        scope: 'target',
        target: 'ARGS:note',
        reason: 'Mẫu xem thử: ghi chú giao dịch',
        expires_at: new Date(now + 86400000).toISOString(),
        enabled: true,
        source: 'manual'
    }
];
const fixtures = [
    [942100, 'GET', '/api/lab/search', 'ARGS:q', 128, '2', 'candidate'],
    [941100, 'POST', '/api/lab/transfer', 'ARGS:note', 64, '2', 'needs_review'],
    [930100, 'GET', '/api/lab/file', 'ARGS:path', 47, '2', 'candidate'],
    [920350, 'GET', '/api/lab/documents/102', 'REQUEST_HEADERS:Host', 32, '4', 'candidate'],
    [942430, 'GET', '/api/lab/search', 'ARGS:q', 24, '2', 'confirmed_fp'],
    [920300, 'POST', '/api/lab/login', 'REQUEST_HEADERS:Accept', 19, '5', 'dismissed'],
    [941160, 'GET', '/api/lab/xss', 'ARGS:content', 17, '2', 'candidate'],
    [920420, 'POST', '/api/lab/upload', 'REQUEST_HEADERS:Content-Type', 15, '2', 'needs_review'],
    [942200, 'GET', '/api/lab/search', 'ARGS:q', 12, '2', 'candidate'],
    [920320, 'GET', '/api/lab/documents/101', 'REQUEST_HEADERS:User-Agent', 9, '5', 'dismissed'],
    [942260, 'POST', '/api/lab/transfer', 'ARGS:note', 8, '2', 'candidate'],
    [941180, 'GET', '/api/lab/xss', 'ARGS:content', 6, '2', 'confirmed_fp']
];
export const demoLearning = fixtures.map(([rule_id, method, path, parameter, count, severity, status], i) => ({
    key: `demo-${i}`,
    status,
    review_note: '',
    updated_at: new Date(now).toISOString(),
    document: {
        site: 'finance-vulnerable',
        rule_id,
        method,
        path,
        parameter,
        count,
        severity,
        severity_syslog: Number(severity),
        severity_source: severity,
        days: 3,
        pl: i % 3 + 1,
        estimated_blocks: Math.round(count * .65),
        first_seen: new Date(now - 3 * 86400000).toISOString(),
        last_seen: new Date(now - i * 900000).toISOString(),
        sample_request_ids: [`demo-request-${String(i+1).padStart(4,'0')}`]
    }
}));
export const demoHealth = {
    worker_last_seen: new Date(now - 24000).toISOString(),
    automation: demoPolicy.automation
};

const demoLogSamples = [
    { '@timestamp': new Date(now - 30000).toISOString(), event: { dataset: 'coraza.audit' }, transaction: { id: 'demo-request-0001', messages: [{ message: 'SQL Injection Attack', details: { ruleId: 942100, match: 'Matched ARGS:q' } }] }, portal: { source_label: 'Coraza audit', source_group: 'waf', category: 'SQL injection', rules: ['942100'], matches: ['Matched ARGS:q'], path: '/api/lab/search', ip: '192.0.2.10', status: 403 } },
    { '@timestamp': new Date(now - 32000).toISOString(), event: { dataset: 'haproxy.access', action: 'request' }, http: { request: { id: 'demo-request-0001' }, response: { status_code: 403 } }, portal: { source_label: 'HAProxy access', source_group: 'haproxy', category: null, rules: [], matches: [], path: '/api/lab/search', ip: '192.0.2.10', status: 403 } }
];
export const demoLogs = Array.from({ length: 30 }, (_, index) => {
    const row = structuredClone(demoLogSamples[index % demoLogSamples.length]);
    row['@timestamp'] = new Date(now - 30000 - Math.floor(index / 2) * 86400000 - (index % 2) * 2000).toISOString();
    const requestId = `demo-request-${String(Math.floor(index / 2) + 1).padStart(4, '0')}`;
    if (row.transaction) {
        row.transaction.id = `coraza-${requestId}`;
        row.transaction.request = { method: 'GET', headers: { 'x-request-id': [requestId], 'x-lab-mode': ['DetectionOnly'] } };
        row.transaction.is_interrupted = true;
    }
    if (row.http?.request) row.http.request.id = requestId;
    if (row.transaction) row.portal.correlation = { request_id: requestId, haproxy: {
        request_id: requestId, client_ip: row.portal.ip, method: 'GET', path: row.portal.path,
        status: row.portal.status, route: 'waf', backend: 'finance_waf_with_fallback', server: 'waf'
    } };
    return row;
});
for (const row of demoLogs.filter(item => item.http?.request?.id === 'demo-request-0002' || item.transaction?.request?.headers?.['x-request-id']?.[0] === 'demo-request-0002')) {
    row.portal.status = 200;
    row.portal.category = null;
    row.portal.rules = [];
    if (row.http?.response) row.http.response.status_code = 200;
    if (row.transaction) { row.transaction.is_interrupted = false; row.transaction.messages = []; }
}
demoLogs.splice(4, 0, { '@timestamp': new Date(now - 86435000).toISOString(), event: { dataset: 'finance.lab', action: 'search' }, http: { request: { id: 'demo-request-0002' }, response: { status_code: 200 } }, portal: { source_label: 'Finance', source_group: 'finance', category: null, rules: [], path: '/api/lab/search', ip: '192.0.2.10', status: 200 } });
demoLogs.splice(5, 0, { '@timestamp': new Date(now - 36000).toISOString(), event: { dataset: 'haproxy.system', action: 'stopped' }, message: 'Proxy lab_http stopped (cumulated conns: FE: 0, BE: 0).', portal: { source_label: 'HAProxy hệ thống', source_group: 'haproxy', explanation: 'Proxy lab_http đã dừng. Không có request nào bị chặn bởi thông báo này.' } });
