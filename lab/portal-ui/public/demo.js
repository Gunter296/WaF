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
    [942100, 'GET', '/api/lab/search', 'ARGS:q', 128, 'high', 'candidate'],
    [941100, 'POST', '/api/lab/transfer', 'ARGS:note', 64, 'high', 'needs_review'],
    [930100, 'GET', '/api/lab/file', 'ARGS:path', 47, 'critical', 'candidate'],
    [920350, 'GET', '/api/lab/documents/102', 'REQUEST_HEADERS:Host', 32, 'medium', 'candidate'],
    [942430, 'GET', '/api/lab/search', 'ARGS:q', 24, 'medium', 'confirmed_fp'],
    [920300, 'POST', '/api/lab/login', 'REQUEST_HEADERS:Accept', 19, 'low', 'dismissed'],
    [941160, 'GET', '/api/lab/xss', 'ARGS:content', 17, 'high', 'candidate'],
    [920420, 'POST', '/api/lab/upload', 'REQUEST_HEADERS:Content-Type', 15, 'medium', 'needs_review'],
    [942200, 'GET', '/api/lab/search', 'ARGS:q', 12, 'high', 'candidate'],
    [920320, 'GET', '/api/lab/documents/101', 'REQUEST_HEADERS:User-Agent', 9, 'low', 'dismissed'],
    [942260, 'POST', '/api/lab/transfer', 'ARGS:note', 8, 'medium', 'candidate'],
    [941180, 'GET', '/api/lab/xss', 'ARGS:content', 6, 'medium', 'confirmed_fp']
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