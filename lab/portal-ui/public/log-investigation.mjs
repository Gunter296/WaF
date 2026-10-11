const hiddenKey = /(?:authorization|cookie|token|jwt|password|passwd|secret|api[-_]?key|session|credential|private[-_]?key|email|phone|address|birth|card|cvv|ssn|account|iban|identity|tax[-_]?id|user[-_]?id|full[-_]?name|first[-_]?name|last[-_]?name)/i;
const relevantHeader = /^(?:host|user-agent|content-type|accept|x-request-id|x-lab-[a-z0-9-]+|x-waf-lab-[a-z0-9-]+|x-forwarded-proto)$/i;
const mask = '[đã che]';
const transactionOf = row => row?.transaction || row?.audit_data?.transaction || {};
const auditMessagesOf = row => {
    const nested = transactionOf(row).messages;
    if (Array.isArray(nested) && nested.length) return nested;
    const root = row?.messages || row?.audit_data?.messages;
    return Array.isArray(root) ? root : [];
};

export function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
}

export function redactText(value) {
    return String(value ?? '')
        .replace(/([?&](?:[^=&]*(?:token|jwt|password|secret|key|session|email|phone|card)[^=&]*)=)[^&\s]*/ig, '$1' + mask)
        .replace(/\bBearer\s+[^\s,;]+/ig, 'Bearer ' + mask)
        .replace(/\b(Authorization|Cookie|Set-Cookie)\s*[:=]\s*[^\r\n]*/ig, function (_, name) { return name + ': ' + mask; })
        .replace(/\b(Password|Token|JWT|Api-Key)\s*[:=]\s*[^\s,;]+/ig, function (_, name) { return name + ': ' + mask; })
        .replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, mask)
        .replace(/\+\d{1,3}[ .-]?(?:\d[ .-]?){8,12}/g, mask)
        .replace(/\b0(?:\d[ .-]?){9,10}\b/g, mask)
        .replace(/\b(?:\d[ -]*?){13,19}\b/g, mask);
}

export function redactLog(value, key = '', depth = 0) {
    if (hiddenKey.test(key) && !/^(?:tokens_remaining|bucket_capacity)$/i.test(key)) return mask;
    if (depth > 16) return '[đã lược bớt: quá sâu]';
    if (Array.isArray(value)) {
        const items = value.slice(0, 200).map(item => redactLog(item, '', depth + 1));
        if (value.length > 200) items.push('[đã giới hạn 200 phần tử]');
        return items;
    }
    if (value && typeof value === 'object') {
        const entries = Object.entries(value);
        const result = Object.fromEntries(entries.slice(0, 250).map(([name, item]) => [name, redactLog(item, name, depth + 1)]));
        if (entries.length > 250) result['[đã giới hạn]'] = 'Chỉ hiển thị 250 trường đầu';
        return result;
    }
    if (typeof value !== 'string') return value;
    if (/^(?:body|raw_body|request_body)$/i.test(key)) {
        try { return redactLog(JSON.parse(value), '', depth + 1); }
        catch { return '[đã che: body không có cấu trúc JSON]'; }
    }
    const text = redactText(value);
    return text.length > 4000 ? text.slice(0, 4000) + ' [đã giới hạn 4000 ký tự]' : text;
}

export function renderInvestigationDecisions(decisions) {
    if (!decisions.length) return '<p class="trace-muted">Không có rule hoặc quyết định WAF trong các bản ghi ghép theo ID.</p>';
    const hasValue = value => value !== undefined && value !== null && value !== '';
    const shown = (value, limit = 320) => {
        if (!hasValue(value)) return 'Không có trong log';
        const clean = redactText(typeof value === 'object' ? JSON.stringify(redactLog(value)) : String(value));
        return escapeHtml(clean.length > limit ? clean.slice(0, limit) + ' [đã giới hạn ' + limit + ' ký tự]' : clean);
    };
    const item = (name, value, limit) => '<div class="trace-field"><dt>' + escapeHtml(name) + '</dt><dd>' + shown(value, limit) + '</dd></div>';
    const optionalItem = (name, value, limit) => hasValue(value) ? item(name, value, limit) : '';
    return decisions.map(decision => {
        const policy = decision.policy || {};
        const heading = decision.kind === 'coraza-transaction' ? 'Kết quả Coraza' :
            decision.kind === 'coraza-rule' ? 'Rule Coraza khớp' : 'Policy WAF';
        let fields;
        if (decision.kind === 'coraza-transaction') {
            fields = item('Bằng chứng', decision.action) + item('Kết luận', decision.verdict);
        } else if (decision.kind === 'coraza-rule') {
            fields = optionalItem('Rule ID', decision.rule) + optionalItem('Rule message', decision.message, 500) +
                item('Kết quả rule', decision.verdict) + optionalItem('Vị trí / dữ liệu khớp', decision.target, 700) +
                optionalItem('Score ghi trong log', decision.score);
        } else {
            const counter = policy.counter_type === 'token_bucket' && hasValue(policy.tokens_remaining) && hasValue(policy.bucket_capacity)
                ? 'Token còn ' + policy.tokens_remaining + ' / sức chứa ' + policy.bucket_capacity
                : hasValue(policy.count) && hasValue(policy.limit) ? policy.count + ' / ngưỡng ' + policy.limit : null;
            fields = optionalItem('Rule policy', decision.rule) + optionalItem('Thông điệp', decision.message, 500) +
                optionalItem('Path áp dụng', decision.path, 700) + optionalItem('Action trong log', decision.action) +
                item('Kết quả request', decision.verdict) + optionalItem('Loại bộ đếm', policy.counter_type) +
                optionalItem('Bộ đếm / ngưỡng', counter) + optionalItem('Cửa sổ (giây)', policy.window_seconds) +
                optionalItem('Action cấu hình', policy.configured_action) + optionalItem('Action thực thi', policy.effective_action) +
                optionalItem('Score ghi trong log', decision.score);
        }
        const at = decision.at ? new Date(decision.at).toLocaleString('vi-VN') : 'Chưa có';
        return '<article class="trace-decision"><strong>' + escapeHtml(heading) + ' · ' + shown(decision.source) +
            '</strong><time>' + shown(at) + '</time><dl class="trace-fields">' + fields + '</dl></article>';
    }).join('');
}

export function requestIdOf(row) {
    const headers = transactionOf(row).request?.headers || row.request?.headers || {};
    const header = Object.entries(headers).find(([name]) => name.toLowerCase() === 'x-request-id')?.[1];
    const id = row.http?.request?.id || (Array.isArray(header) ? header[0] : header) || row.lab?.request_id || row.portal?.correlation?.request_id || '';
    return id && id !== '-' && id !== 'direct' ? String(id) : '';
}

export function investigateRequest(rows, id) {
    const records = rows.filter(row => requestIdOf(row) === id).sort((a, b) => Date.parse(a['@timestamp'] || 0) - Date.parse(b['@timestamp'] || 0));
    const source = row => row.portal?.source_label || row.event?.dataset || 'Nguồn khác';
    const proxy = records.find(row => row.portal?.source_group === 'haproxy' && row.event?.dataset === 'haproxy.access');
    const audit = records.filter(row => row.portal?.source_label === 'Coraza audit' || row.event?.dataset === 'coraza.audit');
    const policies = records.filter(row => row.event?.dataset === 'waf.behavior');
    const finance = records.filter(row => row.portal?.source_group === 'finance' || row.event?.dataset === 'finance.lab');
    const wafAccess = records.filter(row => row.portal?.source_label === 'WAF access' || row.event?.dataset === 'waf.access');
    const requestRow = audit.find(row => transactionOf(row).request) || wafAccess.find(row => row.request) || proxy || records[0];
    const request = transactionOf(requestRow).request || requestRow?.request || {};
    const headers = request.headers || {};
    const header = name => {
        const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name)?.[1];
        return Array.isArray(value) ? value[0] : value;
    };
    const policyInfo = policies.map(row => row.waf?.policy || row.portal?.policy_evidence).find(Boolean);
    const route = proxy?.lab || records.map(row => row.portal?.correlation?.haproxy).find(Boolean) || {};
    const statuses = [...new Set(records.filter(row => ['haproxy.access', 'waf.access', 'coraza.audit', 'waf.behavior'].includes(row.event?.dataset) ||
        ['HAProxy access', 'WAF access', 'Coraza audit', 'WAF policy'].includes(row.portal?.source_label))
        .map(row => row.http?.response?.status_code ?? row.status ?? transactionOf(row).response?.http_code ?? row.portal?.status)
        .filter(value => value != null).map(Number).filter(Number.isFinite))];
    const status = proxy?.http?.response?.status_code ?? statuses[0] ?? null;
    const corazaBlocked = audit.some(row => transactionOf(row).is_interrupted === true || row.is_interrupted === true);
    const policyBlocked = policies.some(row => row.event?.kind === 'blocked' && row.event?.action === 'block' && row.waf?.policy?.actual_block !== false);
    const appRejected = finance.some(row => row.event?.outcome === 'application_rejected' || Number(row.portal?.status) >= 400);
    const appSeen = finance.length > 0;
    const threshold = policies.some(row => row.event?.kind === 'behavior' && row.event?.action === 'block');
    const observed = policies.some(row => row.event?.kind === 'behavior' && row.event?.action === 'observe');
    const scanner = audit.some(row => auditMessagesOf(row).some(message => /^913\d{3}$/.test(String(message.details?.ruleId || message.details?.id || message.data?.id || '')) ||
        (message.details?.tags || message.data?.tags || []).some(tag => String(tag).toLowerCase().includes('attack-scanner'))));
    const policyType = policies.some(row => /^(?:bot_|bot-)/.test(String(row.rule?.id || ''))) ? 'Bot policy'
        : policies.some(row => /rate_limit/.test(String(row.rule?.id || ''))) ? 'Rate limit'
        : 'Behavior policy';
    const fallback = route.backend === 'finance_waf_with_fallback' && route.server === 'finance-fallback';
    const bypass = fallback || route.backend === 'finance_direct' || route.route === 'bypass';
    const policyContradiction = policies.some(row => row.event?.kind === 'blocked' && row.waf?.policy?.actual_block === false);
    const conflicting = statuses.length > 1 || ((corazaBlocked || policyBlocked) && appSeen) || (corazaBlocked && policyBlocked) ||
        ((corazaBlocked || policyBlocked) && status != null && Number(status) < 400) ||
        (appRejected && status != null && Number(status) < 400) || (bypass && (corazaBlocked || policyBlocked)) || policyContradiction;
    let title = 'Chưa rõ nguồn xử lý';
    let responseSource = 'Chưa xác định';
    if (conflicting) title = 'Kết quả không thống nhất giữa các log';
    else if (corazaBlocked) { title = 'Coraza chặn'; responseSource = 'Coraza audit'; }
    else if (policyBlocked) { title = policyType + ' chặn'; responseSource = 'WAF policy'; }
    else if (appRejected) { title = 'Ứng dụng từ chối' + (status != null ? ' (HTTP ' + status + ')' : ''); responseSource = 'Finance'; }
    else if (observed) title = policyType + ' observe';
    else if (threshold) title = policyType + ' đạt ngưỡng; chưa có bằng chứng chặn request này';
    else if (scanner) title = 'Scanner được nhận diện; chưa có bằng chứng chặn';
    else if (status != null && Number(status) >= 500) title = 'HTTP ' + status + '; chưa rõ proxy hay upstream';
    else if (status != null && Number(status) >= 400) title = 'HTTP ' + status + '; chưa rõ nguồn từ chối';
    else if (status != null) title = 'HTTP ' + status + '; chưa có bằng chứng chặn';
    if (conflicting) responseSource = 'Các nguồn không thống nhất';
    const historicalModeRow = records.find(row => row.portal?.waf_mode_source);
    const modeSource = bypass ? 'Không áp dụng: request không qua WAF'
        : header('x-lab-mode') ? 'Coraza audit: request.headers.x-lab-mode'
        : policyInfo?.mode ? 'WAF policy: waf.policy.mode'
        : historicalModeRow?.portal?.waf_mode_source || 'Không xác minh được lịch sử';
    const mode = bypass ? 'Không áp dụng (request không qua WAF)' : header('x-lab-mode') || policyInfo?.mode || historicalModeRow?.portal?.waf_mode ||
        records.find(row => row.portal?.waf_mode)?.portal?.waf_mode || null;
    const decisionRows = [...audit, ...policies].sort((a, b) => Date.parse(a['@timestamp'] || 0) - Date.parse(b['@timestamp'] || 0));
    const decisions = decisionRows.flatMap(row => {
        if (row.event?.dataset === 'waf.behavior') return [{
            kind: 'policy', source: source(row), at: row['@timestamp'], rule: row.rule?.id, message: row.message, action: row.event?.action,
            verdict: row.event?.kind === 'blocked' && row.waf?.policy?.actual_block === false ? 'Log kind và actual_block mâu thuẫn'
                : row.event?.kind === 'blocked' ? 'Request bị chặn' : row.event?.action === 'observe' ? 'Observe, request chưa bị policy chặn' : 'Đạt ngưỡng, chưa có bằng chứng request bị chặn',
            path: row.waf?.policy?.path || row.url?.path, score: row.waf?.policy?.score,
            policy: row.waf?.policy || row.portal?.policy_evidence
        }];
        const messages = auditMessagesOf(row);
        const interrupted = transactionOf(row).is_interrupted === true || row.is_interrupted === true;
        const transactionDecision = interrupted ? [{
            kind: 'coraza-transaction', source: source(row), at: row['@timestamp'], action: 'is_interrupted=true',
            verdict: messages.length ? 'Coraza ghi giao dịch bị ngắt; xem các rule khớp bên dưới'
                : 'Coraza ghi giao dịch bị ngắt; không có rule message trong log'
        }] : [];
        return [...transactionDecision, ...messages.map(message => {
            const details = message.details || message.data || {};
            const target = [details.match, details.data, message.match, typeof message.data === 'string' ? message.data : null]
                .find(value => typeof value === 'string' && value.trim());
            return { kind: 'coraza-rule', source: source(row), at: row['@timestamp'], rule: details.ruleId || details.id || message.ruleId || message.id,
                message: message.message || details.message || details.msg, action: 'rule match',
                verdict: interrupted ? 'Rule khớp trong giao dịch bị ngắt; log không chỉ rõ rule trực tiếp gây ngắt'
                    : 'Rule khớp; không có bằng chứng ngắt',
                target, score: details.score ?? message.score };
        })];
    });
    const expected = ['HAProxy access', 'Coraza audit', 'WAF policy', 'WAF access', 'Finance'];
    const evidence = records.map(row => ({ row, source: source(row), at: row['@timestamp'], id: requestIdOf(row), match: 'Khớp trực tiếp bằng ID' }));
    const missing = expected.filter(name => !evidence.some(item => item.source === name));
    const visibleHeaders = Object.fromEntries(Object.entries(headers).filter(([name]) => relevantHeader.test(name)));
    const bodyEvidence = audit.flatMap(row => row.portal?.body_evidence || []);
    return {
        id, records, title, status, responseSource, conflicting, route, bypass, fallback, appSeen, corazaBlocked, policyBlocked,
        request: { method: request.method || requestRow?.http?.request?.method || requestRow?.portal?.method || null,
            host: request.host || header('host') || null, path: request.uri || requestRow?.url?.path || requestRow?.portal?.path || null,
            ip: proxy?.source?.ip || requestRow?.portal?.ip || null, userAgent: header('user-agent') || policyInfo?.user_agent || null,
            headers: visibleHeaders, full: request },
        decisions, bodyEvidence, evidence, missing,
        config: { mode, modeSource, version: policyInfo?.version ?? null,
            blockingPL: header('x-lab-blocking-pl') || policyInfo?.blocking_pl || null,
            detectionPL: header('x-lab-detection-pl') || policyInfo?.detection_pl || null,
            featureEnabled: typeof policyInfo?.enabled === 'boolean' ? policyInfo.enabled : null,
            featureAction: policyInfo?.configured_action || null,
            featureRule: policies.find(row => row.rule?.id)?.rule?.id || null,
            plSource: header('x-lab-blocking-pl') || header('x-lab-detection-pl') ? 'Coraza audit: request.headers'
                : policyInfo?.blocking_pl != null || policyInfo?.detection_pl != null ? 'WAF policy trong request' : 'Không xác minh được lịch sử',
            featureSource: policyInfo?.configured_action || typeof policyInfo?.enabled === 'boolean'
                ? 'WAF policy trong request' : 'Không xác minh được lịch sử' }
    };
}
