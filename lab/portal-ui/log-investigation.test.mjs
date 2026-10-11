import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, investigateRequest, redactLog, redactText, renderInvestigationDecisions, requestIdOf } from './public/log-investigation.mjs';
import { fetchRequestTrace } from './logs.mjs';

const id = 'LAB-TRACE-1';
const haproxy = (status, server = 'waf', backend = 'finance_waf_with_fallback') => ({
    '@timestamp': '2026-10-09T02:00:03Z', event: { dataset: 'haproxy.access' },
    http: { request: { id, method: 'GET' }, response: { status_code: status } },
    source: { ip: '192.0.2.8' }, url: { path: '/api/lab/search' },
    lab: { route: server === 'waf' ? 'waf' : 'bypass', backend, server },
    portal: { source_group: 'haproxy', source_label: 'HAProxy access', status }
});
const audit = (interrupted, rule = 913100) => ({
    '@timestamp': '2026-10-09T02:00:02Z', event: { dataset: 'coraza.audit' },
    transaction: { is_interrupted: interrupted, request: { method: 'GET', uri: '/api/lab/search',
        headers: { 'x-request-id': id, Host: 'localhost', 'User-Agent': 'nuclei', 'X-Lab-Mode': 'On',
            'X-Lab-Blocking-PL': '1', Authorization: 'TEST_ONLY_VALUE' } },
        messages: [{ message: 'Scanner detected', details: { ruleId: rule, match: 'REQUEST_HEADERS:User-Agent' } }] },
    portal: { source_group: 'waf', source_label: 'Coraza audit', body_evidence: [] }
});
const policy = (kind, action, rule = 'rate_limit', status = null) => ({
    '@timestamp': '2026-10-09T02:00:01Z', event: { dataset: 'waf.behavior', kind, action },
    http: { request: { id }, ...(status ? { response: { status_code: status } } : {}) },
    rule: { id: rule }, message: 'Threshold reached',
    waf: { policy: { count: 16, limit: 15, window_seconds: 30, configured_action: 'block',
        effective_action: kind === 'blocked' ? 'block' : 'none', actual_block: kind === 'blocked',
        decision_result: kind === 'blocked' ? 'blocked' : 'threshold_reached' } },
    portal: { source_group: 'waf', source_label: 'WAF policy' }
});
const finance = outcome => ({
    '@timestamp': '2026-10-09T02:00:02Z', event: { dataset: 'finance.lab', outcome },
    http: { request: { id } }, portal: { source_group: 'finance', source_label: 'Finance' }
});

test('Coraza interrupt is a block; a matching scanner rule without interrupt is only recognition', () => {
    const blocked = investigateRequest([audit(true), haproxy(403)], id);
    assert.equal(blocked.title, 'Coraza chặn');
    assert.equal(blocked.responseSource, 'Coraza audit');
    const recognized = investigateRequest([audit(false), haproxy(404)], id);
    assert.match(recognized.title, /Scanner được nhận diện/);
    assert.equal(recognized.responseSource, 'Chưa xác định');
    assert.match(recognized.decisions[0].verdict, /không có bằng chứng ngắt/);
});

test('Coraza root messages remain visible as decisions when transaction carries the interrupt', () => {
    const row = audit(true);
    row.messages = [{ message: 'Scanner rule matched', data: { id: '913100', msg: 'Scanner Detection',
        tags: ['attack-scanner'], data: 'REQUEST_HEADERS:User-Agent' } }];
    row.transaction.messages = [];
    const result = investigateRequest([row, haproxy(403)], id);
    assert.equal(result.title, 'Coraza chặn');
    assert.equal(result.decisions.length, 2);
    assert.equal(result.decisions[0].action, 'is_interrupted=true');
    assert.equal(result.decisions[0].rule, undefined);
    assert.equal(result.decisions[1].rule, '913100');
    assert.equal(result.decisions[1].message, 'Scanner rule matched');
    assert.equal(result.decisions[1].action, 'rule match');
    assert.match(result.decisions[1].verdict, /không chỉ rõ rule trực tiếp gây ngắt/);
    assert.equal(result.decisions[1].target, 'REQUEST_HEADERS:User-Agent');
});

test('interrupted Coraza audit without messages shows the interrupt and no invented rule', () => {
    const row = audit(true);
    delete row.transaction.messages;
    const result = investigateRequest([row, haproxy(403)], id);
    assert.equal(result.title, 'Coraza chặn');
    assert.equal(result.decisions.length, 1);
    assert.equal(result.decisions[0].rule, undefined);
    assert.equal(result.decisions[0].action, 'is_interrupted=true');
    assert.match(result.decisions[0].verdict, /không có rule message/);
});

test('Coraza decisions show only audit evidence; absent policy counters and actions do not occupy the UI', () => {
    const row = audit(true);
    row.messages = [{ message: 'SQLi match', data: { id: 942100, data: 'Matched Data: value found within ARGS:q' } },
        { message: 'Anomaly threshold', data: { id: 949110, data: '' } }];
    delete row.transaction.messages;
    const html = renderInvestigationDecisions(investigateRequest([row, haproxy(403)], id).decisions);
    assert.match(html, /Kết quả Coraza/);
    assert.match(html, /942100/);
    assert.match(html, /Vị trí \/ dữ liệu khớp/);
    assert.equal((html.match(/Vị trí \/ dữ liệu khớp/g) || []).length, 1);
    for (const label of ['Bộ đếm', 'Cửa sổ', 'Action cấu hình', 'Action thực thi', 'Score ghi trong log']) {
        assert.equal(html.includes(label), false, label);
    }
});

test('policy decisions show actual counters and configured versus effective actions', () => {
    const countHtml = renderInvestigationDecisions(investigateRequest([policy('behavior', 'block')], id).decisions);
    assert.match(countHtml, /Bộ đếm \/ ngưỡng/);
    assert.match(countHtml, /16 \/ ngưỡng 15/);
    assert.match(countHtml, /Cửa sổ \(giây\)/);
    assert.match(countHtml, /Action cấu hình/);
    assert.match(countHtml, /Action thực thi/);
    assert.match(countHtml, /threshold reached|Đạt ngưỡng/i);
    assert.equal(countHtml.includes('Vị trí / dữ liệu khớp'), false);
    const token = policy('blocked', 'block', 'bot_request_rate');
    token.waf.policy = { counter_type: 'token_bucket', tokens_remaining: 0, bucket_capacity: 10,
        window_seconds: 30, configured_action: 'block', effective_action: 'block', actual_block: true };
    const tokenHtml = renderInvestigationDecisions(investigateRequest([token], id).decisions);
    assert.match(tokenHtml, /Token còn 0 \/ sức chứa 10/);
    assert.equal(tokenHtml.includes('Không có trong log'), false);
});

test('decision HTML escapes rule text and masks sensitive matched data', () => {
    const row = audit(false);
    row.messages = [{ message: '<img src=x onerror=alert(1)>', data: { id: 942100,
        data: 'Matched Data: token=PRIVATE_TEST_MARKER found within ARGS:q' } }];
    delete row.transaction.messages;
    const html = renderInvestigationDecisions(investigateRequest([row], id).decisions);
    assert.equal(html.includes('<img'), false);
    assert.match(html, /&lt;img/);
    assert.equal(html.includes('PRIVATE_TEST_MARKER'), false);
});

test('bot, behavior and rate thresholds do not imply a block for the same request', () => {
    for (const rule of ['bot_declared_fanout', 'not_found_burst', 'rate_limit']) {
        const threshold = investigateRequest([policy('behavior', 'block', rule), haproxy(200)], id);
        assert.match(threshold.title, /đạt ngưỡng/);
        assert.equal(threshold.policyBlocked, false);
        assert.equal(threshold.decisions[0].policy.count, 16);
        const observed = investigateRequest([policy('behavior', 'observe', rule), haproxy(200)], id);
        assert.match(observed.title, /observe$/);
    }
    const blocked = investigateRequest([policy('blocked', 'block', 'rate_limit', 429), haproxy(429)], id);
    assert.equal(blocked.title, 'Rate limit chặn');
    assert.equal(blocked.responseSource, 'WAF policy');
});

test('application rejection, unknown 403, fallback and conflicting sources stay distinct', () => {
    const app = investigateRequest([finance('application_rejected'), haproxy(401)], id);
    assert.equal(app.title, 'Ứng dụng từ chối (HTTP 401)');
    assert.equal(app.responseSource, 'Finance');
    const unknown = investigateRequest([haproxy(403)], id);
    assert.match(unknown.title, /chưa rõ nguồn từ chối/);
    const fallback = investigateRequest([haproxy(404, 'finance-fallback')], id);
    assert.equal(fallback.fallback, true);
    assert.equal(fallback.appSeen, false);
    assert.match(fallback.config.mode, /Không áp dụng/);
    const conflicting = investigateRequest([policy('blocked', 'block', 'rate_limit', 429), haproxy(404)], id);
    assert.equal(conflicting.conflicting, true);
    assert.match(conflicting.title, /không thống nhất/);
    assert.equal(investigateRequest([finance('application_rejected'), haproxy(200)], id).conflicting, true);
    assert.equal(investigateRequest([policy('blocked', 'block', 'rate_limit', 429), haproxy(429, 'finance-fallback')], id).conflicting, true);
});

test('request ID and absence of a source are explicit', () => {
    assert.equal(requestIdOf({ event: { dataset: 'haproxy.system' } }), '');
    assert.equal(requestIdOf({ http: { request: { id: 'direct' } } }), '');
    assert.equal(requestIdOf({ audit_data: { transaction: { request: { headers: { 'x-request-id': [id] } } } } }), id);
    const result = investigateRequest([audit(false)], id);
    assert.deepEqual(result.missing.includes('HAProxy access'), true);
    assert.equal(result.evidence[0].match, 'Khớp trực tiếp bằng ID');
    assert.equal(result.config.mode, 'On');
    assert.equal(result.config.version, null);
});

test('headers, body and raw JSON redact private markers without changing input', () => {
    const original = { request: { headers: { Authorization: 'PRIVATE_TEST_MARKER', Cookie: 'PRIVATE_TEST_MARKER',
        'X-Request-ID': id }, body: JSON.stringify({ password: 'PRIVATE_TEST_MARKER', note: 'safe' }) },
        message: 'token=PRIVATE_TEST_MARKER', email: 'PRIVATE_TEST_MARKER' };
    const redacted = redactLog(original);
    const displayed = JSON.stringify(redacted);
    assert.equal(displayed.includes('PRIVATE_TEST_MARKER'), false);
    assert.equal(displayed.includes(id), true);
    assert.equal(redacted.request.body.note, 'safe');
    assert.equal(original.request.headers.Authorization, 'PRIVATE_TEST_MARKER');
    assert.equal(redactText('/path?api_key=PRIVATE_TEST_MARKER').includes('PRIVATE_TEST_MARKER'), false);
    assert.equal(redactText('Cookie: first=PRIVATE_TEST_MARKER; second=PRIVATE_TEST_MARKER').includes('PRIVATE_TEST_MARKER'), false);
    assert.equal(redactText('Liên hệ test@example.invalid').includes('test@example.invalid'), false);
    assert.equal(redactLog('PRIVATE_TEST_MARKER', 'body'), '[đã che: body không có cấu trúc JSON]');
    assert.deepEqual(redactLog({ tokens_remaining: 2, bucket_capacity: 10 }), { tokens_remaining: 2, bucket_capacity: 10 });
    assert.equal(escapeHtml('<img src=x onerror="alert(1)">'), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
});

test('trace API accepts exact X-Request-ID, rejects fuzzy hits and attaches historical mode only from prior audit', async () => {
    const calls = [];
    const matching = { '@timestamp': '2026-10-09T02:00:00Z', event: { dataset: 'haproxy.access' },
        http: { request: { id } }, lab: { server: 'waf', backend: 'finance_waf_with_fallback' },
        input: { type: 'udp' } };
    const near = { ...matching, http: { request: { id: id + '-OTHER' } } };
    const fetchFn = async (_url, options) => {
        calls.push(JSON.parse(options.body));
        return { ok: true, json: async () => calls.length === 1
            ? { hits: { total: { value: 2 }, hits: [{ _source: matching }, { _source: near }] } }
            : { hits: { hits: [{ _source: { '@timestamp': '2026-10-09T01:00:00Z', lab: { mode: 'DetectionOnly' } } }] } } };
    };
    const result = await fetchRequestTrace(id, 'http://elastic.test', fetchFn);
    assert.equal(result.items.length, 1);
    assert.equal(result.items[0].portal.waf_mode, 'DetectionOnly');
    assert.equal(result.truncated, false);
    assert.equal(calls.length, 2);
});
