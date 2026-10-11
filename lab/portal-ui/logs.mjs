import { isIP } from "node:net";

export const LOG_PAGE_SIZE = 25;
const PIT_KEEP_ALIVE = "2m";
const compactLogSource = { excludes: ["transaction.request.body", "transaction.response.body",
  "audit_data.transaction.request.body", "audit_data.transaction.response.body"] };

const fileSources = {
  "waf-access.jsonl": ["waf.access", "WAF access", "waf"],
  "waf-policy.jsonl": ["waf.behavior", "WAF policy", "waf"],
  "coraza-audit.jsonl": ["coraza.audit", "Coraza audit", "waf"],
  "portal.jsonl": ["portal.audit", "Portal audit", "portal"]
};
const datasetSources = {
  "waf.access": ["WAF access", "waf"], "waf.behavior": ["WAF policy", "waf"],
  "coraza.audit": ["Coraza audit", "waf"], "portal.audit": ["Portal audit", "portal"],
  "finance.lab": ["Finance", "finance"], "haproxy.access": ["HAProxy access", "haproxy"]
};

const fileMatch = names => ({ bool: { should: names.map(name => ({ wildcard: { "log.file.path": `*${name}` } })), minimum_should_match: 1 } });
const wafSource = { bool: { should: [fileMatch(["waf-access.jsonl", "waf-policy.jsonl", "coraza-audit.jsonl"]), { term: { "event.dataset": "waf.behavior" } }, { term: { "event.dataset": "coraza.audit" } }, { prefix: { logger: "http.log.access" } }], minimum_should_match: 1 } };
const financeSource = { bool: { should: [{ wildcard: { "log.file.path": "*finance*.jsonl" } }, { term: { "event.dataset": "finance.lab" } }], minimum_should_match: 1 } };
const portalSource = { bool: { should: [fileMatch(["portal.jsonl"]), { term: { "event.dataset": "portal.audit" } }], minimum_should_match: 1 } };
const knownSources = [{ term: { "input.type": "udp" } }, wafSource, financeSource, portalSource];
const hiddenHealthChecks = [
  { term: { "url.path": "/healthz" } }, { term: { "url.original": "/healthz" } },
  { term: { "http.request.path": "/healthz" } }, { term: { "request.path": "/healthz" } },
  { term: { "request.uri": "/healthz" } }, { term: { "request.uri.keyword": "/healthz" } },
  { term: { "transaction.request.uri": "/healthz" } }, { term: { "transaction.request.uri.keyword": "/healthz" } },
  { match_phrase: { message: "/healthz" } }
];
const ruleFamily = (prefix, tag) => ({ bool: { should: [
  { range: { "transaction.messages.details.ruleId": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "transaction.messages.details.id": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "transaction.messages.data.ruleId": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "transaction.messages.data.id": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "messages.details.ruleId": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "messages.data.id": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "rule.id": { gte: `${prefix}000`, lt: `${Number(prefix) + 1}000` } } },
  { match_phrase: { "transaction.messages.details.tags": tag } },
  { match_phrase: { "transaction.messages.data.tags": tag } },
  { match_phrase: { "messages.details.tags": tag } },
  { match_phrase: { "messages.data.tags": tag } }
], minimum_should_match: 1 } });
const categoryFilters = {
  sqli: ruleFamily("942", "attack-sqli"), xss: ruleFamily("941", "attack-xss"), rce: ruleFamily("932", "attack-rce"), lfi: ruleFamily("930", "attack-lfi"),
  ssrf: { bool: { should: [{ terms: { "transaction.messages.details.ruleId": [934110, 934120] } }, { terms: { "transaction.messages.data.id": [934110, 934120] } }, { term: { "transaction.messages.details.tags": "attack-ssrf" } }, { term: { "transaction.messages.data.tags": "attack-ssrf" } }], minimum_should_match: 1 } },
  cve: { bool: { should: [{ terms: { "transaction.messages.details.ruleId": [100010, 100011] } }, { terms: { "transaction.messages.details.id": [100010, 100011] } }, { terms: { "transaction.messages.data.id": [100010, 100011] } }, { terms: { "rule.id": ["100010", "100011"] } }, { wildcard: { message: "*CVE-????-????*" } }, { wildcard: { "transaction.messages.message": "*CVE-????-????*" } }], minimum_should_match: 1 } },
  bot: { bool: { should: [{ terms: { "rule.id": ["bot_declared_fanout", "bot_request_rate"] } }, { terms: { "event.action": ["bot_detected", "bot_blocked"] } }, { match_phrase: { "transaction.messages.details.tags": "bot-detection" } }, { match_phrase: { "transaction.messages.data.tags": "bot-detection" } }], minimum_should_match: 1 } },
  scanner: { bool: { should: [{ range: { "transaction.messages.details.ruleId": { gte: 913000, lt: 914000 } } }, { range: { "transaction.messages.details.id": { gte: 913000, lt: 914000 } } }, { range: { "transaction.messages.data.id": { gte: 913000, lt: 914000 } } }, { range: { "rule.id": { gte: "913000", lt: "914000" } } }, { match_phrase: { "transaction.messages.details.tags": "attack-scanner" } }, { match_phrase: { "transaction.messages.data.tags": "attack-scanner" } }], minimum_should_match: 1 } },
  behavior: { bool: { should: [{ term: { "event.dataset": "waf.behavior" } }, { terms: { "event.action": ["behavior", "behavior_detected", "geo_block", "geo_observe", "login_burst", "declared_fanout"] } }, { terms: { "rule.id": ["geo_policy", "login_burst", "login_failures", "bot_path_fanout", "bot_declared_fanout"] } }], minimum_should_match: 1 } },
  rate_limit: { bool: { should: [{ terms: { "rule.id": ["rate_limit", "cidr_rate_limit", "bot_request_rate"] } }, { terms: { "event.action": ["rate_limited", "rate_limit"] } }, { match_phrase: { "transaction.messages.details.tags": "rate-limit" } }, { match_phrase: { "transaction.messages.data.tags": "rate-limit" } }], minimum_should_match: 1 } },
  other: { bool: { should: [{ bool: { filter: [portalSource, { exists: { field: "event.action" } }] } }, { bool: { filter: [financeSource, { exists: { field: "event.action" } }] } }, { term: { "event.dataset": "haproxy.system" } }, { terms: { "event.action": ["policy_updated", "learning_updated", "waf_config_reconciled", "tuning_expired", "login_simulation", "search"] } }, { term: { "transaction.is_interrupted": true } }, { term: { "is_interrupted": true } }, ...["transaction.messages.details.ruleId", "transaction.messages.details.id", "transaction.messages.data.id"].map(field => ({ range: { [field]: { gte: 920000, lt: 921000 } } })), ...["transaction.messages.details.ruleId", "transaction.messages.details.id", "transaction.messages.data.id"].map(field => ({ range: { [field]: { gte: 934000, lt: 935000 } } }))], minimum_should_match: 1 } },
  unclassified: { bool: { must_not: [] } }
};
const rawOtherFilter = categoryFilters.other;
const categoryPriority = ["cve", "sqli", "xss", "rce", "lfi", "ssrf", "bot", "rate_limit", "scanner", "behavior"];
const classifiedBaseFilters = [];
for (const key of categoryPriority) {
  const base = categoryFilters[key];
  categoryFilters[key] = classifiedBaseFilters.length ? { bool: { filter: [base], must_not: [...classifiedBaseFilters] } } : base;
  classifiedBaseFilters.push(base);
}
categoryFilters.other = { bool: { filter: [rawOtherFilter], must_not: classifiedBaseFilters } };
categoryFilters.unclassified = { bool: { must_not: [...classifiedBaseFilters, rawOtherFilter] } };

export function logSearchRequest(params) {
  const pageNumber = Number(params.get("page") || 1);
  if (!Number.isSafeInteger(pageNumber) || pageNumber < 1) throw new Error("invalid log page");
  const page = pageNumber;
  const pitId = params.get("pit") || "";
  const afterText = params.get("after") || "";
  if (pitId.length > 2048 || (pitId && !/^[A-Za-z0-9+/_=-]+$/.test(pitId))) throw new Error("invalid log cursor");
  let after = null;
  if (afterText) {
    if (afterText.length > 512) throw new Error("invalid log cursor");
    try { after = JSON.parse(afterText); } catch { throw new Error("invalid log cursor"); }
    if (!Array.isArray(after) || after.length !== 2 || typeof after[0] !== "string" || !Number.isSafeInteger(after[1])) throw new Error("invalid log cursor");
  }
  if ((page > 1 && (!pitId || !after)) || (page === 1 && after)) throw new Error("missing log cursor");
  const source = params.get("source") || "all";
  if (!["all", "haproxy", "waf", "finance", "portal", "other"].includes(source)) throw new Error("invalid log source");
  const q = (params.get("q") || "").trim();
  if (q.length > 200) throw new Error("log search is too long");
  const category = params.get("category") || "all";
  if (category !== "all" && !Object.hasOwn(categoryFilters, category)) throw new Error("invalid log category");
  const severity = params.get("severity") || "all";
  if (severity !== "all" && !["alert", "high", "warning", "informational", "unknown"].includes(severity)) throw new Error("invalid log severity");
  const status = params.get("status") || "all";
  if (!["all", "2xx", "3xx", "4xx", "5xx", "403"].includes(status)) throw new Error("invalid HTTP status filter");
  const event = (params.get("event") || "").trim();
  const path = (params.get("path") || "").trim();
  const ip = (params.get("ip") || "").trim();
  if ([event, path, ip].some(value => value.length > 120)) throw new Error("log column filter is too long");
  if (ip && !isIP(ip)) throw new Error("IP filter requires a complete IPv4 or IPv6 address");
  const from = params.get("from") || "";
  const to = params.get("to") || "";
  for (const date of [from, to]) if (date && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(date) || Number.isNaN(Date.parse(date)))) throw new Error("invalid log date");
  if (from && to && Date.parse(from) >= Date.parse(to)) throw new Error("log end time must follow start time");
  const filter = [];
  if (from || to) filter.push({ range: { "@timestamp": { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } });
  if (source === "haproxy") filter.push(knownSources[0]);
  if (source === "waf") filter.push(wafSource);
  if (source === "finance") filter.push(financeSource);
  if (source === "portal") filter.push(portalSource);
  if (source === "other") filter.push({ bool: { must_not: knownSources } });
  if (category !== "all") filter.push(categoryFilters[category]);
  const signal = params.get("signal") || "0";
  if (!["0", "1"].includes(signal)) throw new Error("invalid log signal filter");
  if (signal === "1") filter.push(suspiciousWafFilter());
  if (severity !== "all") {
    const groups = { alert: ["EMERGENCY", "EMERG", "0", "ALERT", "1"], high: ["CRITICAL", "2", "ERROR", "3"],
      warning: ["WARNING", "WARN", "4"], informational: ["NOTICE", "5", "INFO", "6", "DEBUG", "7"] };
    filter.push(exclusiveSeverityFilters(groups)[severity]);
  }
  if (status !== "all") {
    const code = status === "403" ? { gte: 403, lt: 404 } : { gte: Number(status[0]) * 100, lt: (Number(status[0]) + 1) * 100 };
    const should = ["http.response.status_code", "status", "transaction.response.http_code"].map(field => ({ range: { [field]: code } }));
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }
  // Column filters only inspect fields that represent that column. Searching an
  // unstructured message here made unrelated prose/body text look like a match.
  if (event) filter.push({ multi_match: { query: event, fields: ["event.action", "event.dataset"], operator: "and" } });
  if (path) filter.push({ bool: { should: ["url.path", "request.uri", "transaction.request.uri", "url.original"].map(field => ({ match_phrase: { [field]: path } })), minimum_should_match: 1 } });
  if (ip) filter.push({ bool: { should: ["source.ip", "client.ip", "request.remote_ip", "transaction.client_ip"].map(field => ({ term: { [field]: ip } })), minimum_should_match: 1 } });
  if (q) {
    const should = [
      { multi_match: { query: q, fields: ["message", "http.request.id", "url.path", "request.uri", "transaction.id", "rule.id", "transaction.messages.details.ruleId", "transaction.messages.data.id", "transaction.messages.message", "transaction.messages.details.message", "transaction.messages.details.data", "transaction.messages.details.match"], operator: "and" } },
      { match_phrase: { "http.request.id": q } }, { match_phrase: { "transaction.id": q } },
      ...["transaction.request.headers.X-Request-ID", "transaction.request.headers.x-request-id", "request.headers.X-Request-ID", "request.headers.x-request-id"].map(field => ({ match_phrase: { [field]: q } })),
      // Older Filebeat UDP events have only the escaped JSON envelope in `message`.
      { bool: { filter: [{ term: { "input.type": "udp" } }, { match_phrase: { message: q } }] } }
    ];
    if (/^[0-9a-fA-F:.]+$/.test(q)) should.push({ term: { "source.ip": q } });
    if (/^\d{5,7}$/.test(q)) should.push({ term: { "rule.id": q } }, { term: { "transaction.messages.details.ruleId": Number(q) } });
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }
  return { page, pitId, after, body: { size: LOG_PAGE_SIZE + 1, track_total_hits: true,
    sort: [{ "@timestamp": { order: "desc", unmapped_type: "date", format: "strict_date_optional_time_nanos" } }], query: { bool: { filter, must_not: hiddenHealthChecks } } } };
}

function parseEmbeddedJson(row) {
  if (row.input?.type !== "udp" || typeof row.message !== "string" || !row.message.trimStart().startsWith("{")) return row;
  try {
    const parsed = JSON.parse(row.message);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return row;
    // Filebeat keeps the original UDP payload as an escaped JSON string. Once decoded,
    // show the structured fields instead of repeating that whole string in `message`.
    const base = { ...row };
    delete base.message;
    return { ...base, ...parsed, "@timestamp": row["@timestamp"] };
  } catch { return row; }
}

function explainEvent(row) {
  const message = String(row.message || "");
  if (row.event?.action === "waf_config_reconciled") return "Caddy đã nạp lại cấu hình WAF thành công";
  const health = message.match(/(?:^|\s)Server\s+([^/\s]+)\/([^\s]+)\s+is\s+(DOWN|UP)(?:\.|,|\s|$)(.*)/i);
  if (health && health[2].toLowerCase() === "waf" && /waf/i.test(health[1])) return health[3].toUpperCase() === "DOWN" ? "WAF down" : "WAF up";
  if (health) return `HAProxy ghi nhận server ${health[2]} thuộc backend ${health[1]} chuyển trạng thái ${health[3].toUpperCase()}.${health[4] ? ` ${health[4].trim()}` : ""}`;
  const stopped = message.match(/^Proxy\s+(.+?)\s+stopped\s+\(cumulated conns:\s*FE:\s*(\d+),\s*BE:\s*(\d+)\)\.?$/i);
  if (stopped) return `Proxy “${stopped[1]}” đã dừng. HAProxy ghi nhận ${stopped[2]} kết nối đi vào (FE) và ${stopped[3]} kết nối tới backend (BE). Đây là thông báo trạng thái, không phải một yêu cầu bị chặn.`;
  if (row.http?.request?.method === "<BADREQ>" || row.url?.path === "<BADREQ>") {
    return `HAProxy nhận được dữ liệu không đúng định dạng HTTP nên trả mã ${row.http?.response?.status_code || 400}. Không đọc được phương thức và đường dẫn của yêu cầu; địa chỉ IP là ${row.source?.ip || "không rõ"}.`;
  }
  return "";
}

function sourceOf(row) {
  const path = String(row.log?.file?.path || "");
  const filename = path.split(/[\\/]/).pop();
  if (fileSources[filename]) return fileSources[filename];
  if (row.input?.type === "udp") return row.event?.dataset === "haproxy.access" ? ["haproxy.access", "HAProxy access", "haproxy"] : ["haproxy.system", "HAProxy hệ thống", "haproxy"];
  if (filename?.startsWith("finance")) return [row.event?.dataset || "finance.lab", "Finance", "finance"];
  if (row.event?.dataset && datasetSources[row.event.dataset]) return [row.event.dataset, ...datasetSources[row.event.dataset]];
  if (row.event?.dataset) return [row.event.dataset, row.event.dataset, "other"];
  if (filename) return [filename, filename, "other"];
  if (row.logger?.startsWith("http.log.access")) return ["waf.access", "WAF access", "waf"];
  return ["unknown", "Không rõ nguồn (thiếu metadata)", "other"];
}

function threatOf(row, dataset) {
  const transaction = row.transaction || row.audit_data?.transaction || {};
  const policyEvidence = row.waf?.policy || row.policy || null;
  const rawMessages = transaction.messages || row.messages || [];
  const messages = Array.isArray(rawMessages) ? rawMessages : [];
  const detailsOf = item => item.details || item.data || {};
  const rules = [row.rule?.id, ...messages.map(item => detailsOf(item).ruleId || detailsOf(item).id || item.ruleId || item.id)].filter(Boolean).map(String);
  const matches = [...new Set(messages.flatMap(item => {
    const details = detailsOf(item);
    const values = [details.match, details.data, item.match, item.data];
    return values.filter(value => typeof value === "string" && value.trim()).map(value => value.slice(0, 240));
  }))].slice(0, 3);
  const tags = messages.flatMap(item => detailsOf(item).tags || item.tags || []).map(String);
  const description = [row.message, ...messages.flatMap(item => [item.message, detailsOf(item).message, detailsOf(item).msg])].filter(Boolean).join(" ");
  const labCves = { "100010": "CVE-2026-64642", "100011": "CVE-2026-64645" };
  const cves = [...new Set([...(description.match(/CVE-\d{4}-\d{4,}/gi) || []).map(value => value.toUpperCase()), ...rules.map(rule => labCves[rule]).filter(Boolean)])];
  const tagText = tags.join(" ").toLowerCase();
  const hasRule = prefix => rules.some(rule => rule.startsWith(prefix));
  const isInterrupted = row.transaction?.is_interrupted === true || row.is_interrupted === true;
  const action = String(row.event?.action || "").toLowerCase();
  const ruleText = rules.join(" ").toLowerCase();
  const isBot = /bot_(declared_fanout|request_rate)|bot[-_ ]detection|bot_detected|bot_blocked/.test(`${ruleText} ${tagText} ${action}`);
  const isScanner = tags.some(tag => tag.toLowerCase().includes("attack-scanner")) || rules.some(rule => /^913\d{3}$/.test(rule));
  const isRateLimit = /rate_limit|rate[-_ ]limit|rate_limited/.test(`${ruleText} ${tagText} ${action}`);
  const isBehavior = dataset === "waf.behavior" || ["behavior", "behavior_detected", "geo_block", "geo_observe", "login_burst", "declared_fanout"].includes(action) || rules.some(rule => ["geo_policy", "login_burst", "login_failures", "bot_path_fanout", "bot_declared_fanout"].includes(rule));
  // The policy module also emits kind=behavior with action=block when a
  // threshold is reached after an upstream 401/404. Only kind=blocked is a
  // decision that actually interrupted this request.
  const policyBlocked = dataset === "waf.behavior" && row.event?.kind === "blocked" && ["block", "blocked"].includes(action);
  const request = transaction.request || row.request || {};
  const headers = request.headers || {};
  const header = name => Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  const modeValue = header("x-lab-mode") || row.lab?.mode || row.lab?.waf_mode || policyEvidence?.mode || "";
  const wafMode = (Array.isArray(modeValue) ? modeValue[0] : modeValue);
  let category = null;
  let categoryKey = "unclassified";
  if (cves.length) category = cves.join(", ");
  else if (tagText.includes("attack-sqli") || hasRule("942")) category = "SQL injection";
  else if (tagText.includes("attack-xss") || hasRule("941")) category = "XSS";
  else if (tagText.includes("attack-rce") || hasRule("932")) category = "Command injection / RCE";
  else if (tagText.includes("attack-lfi") || hasRule("930")) category = "Path traversal / LFI";
  else if (tagText.includes("attack-ssrf") || rules.some(rule => ["934110", "934120"].includes(rule))) category = "SSRF";
  else if (hasRule("934")) category = "Generic application attack";
  else if (tagText.includes("attack-protocol") || hasRule("920")) category = "HTTP protocol";
  else if (isBot) category = "Bot Detection";
  else if (isRateLimit) category = "Rate Limit";
  else if (isScanner) category = "Scanner Detection";
  else if (isBehavior) category = "Behavior";
  else if (isInterrupted) category = "WAF blocked request";
  else if (policyBlocked) category = "WAF behavior policy";
  if (category) {
    if (cves.length) categoryKey = "cve";
    else if (category === "SQL injection") categoryKey = "sqli";
    else if (category === "XSS") categoryKey = "xss";
    else if (category === "Command injection / RCE") categoryKey = "rce";
    else if (category === "Path traversal / LFI") categoryKey = "lfi";
    else if (category === "SSRF") categoryKey = "ssrf";
    else if (category === "Bot Detection") categoryKey = "bot";
    else if (category === "Scanner Detection") categoryKey = "scanner";
    else if (category === "Rate Limit") categoryKey = "rate_limit";
    else if (category === "Behavior") categoryKey = "behavior";
    else categoryKey = "other";
  } else if ((dataset === "portal.audit" || dataset === "finance.lab") && action || dataset === "haproxy.system") categoryKey = "other";
  const bodyEvidence = messages.flatMap(item => {
    const details = detailsOf(item);
    const match = details.data || details.match || item.data || item.match;
    const variable = String(match || "").match(/(?:REQUEST_BODY|ARGS_POST|FILES|XML):?[^\s:]*/i)?.[0] || "";
    return typeof match === "string" && /(?:REQUEST_BODY|ARGS_POST|FILES|XML)/i.test(match)
      ? [{ rule_id: details.ruleId || details.id || item.ruleId || item.id || null, variable, match: match.slice(0, 240), source: "Coraza audit · transaction.messages.details" }]
      : [];
  }).slice(0, 3);
  return { category, category_key: categoryKey, cves, rules: [...new Set(rules)], matches, body_evidence: bodyEvidence,
    waf_mode: ["On", "DetectionOnly", "Off"].includes(wafMode) ? wafMode : null,
    policy_evidence: policyEvidence,
    blocked: isInterrupted || policyBlocked,
    block_source: isInterrupted ? "coraza" : policyBlocked ? "waf_policy" : null };
}

export function normalizeLog(raw) {
  const row = parseEmbeddedJson(raw);
  const transaction = row.transaction || row.audit_data?.transaction || {};
  const [dataset, label, group] = sourceOf(row);
  const threat = threatOf(row, dataset);
  return { ...row, portal: {
    source: dataset, source_label: label, source_group: group,
    explanation: explainEvent(row),
    path: row.url?.path || row.request?.uri || transaction.request?.uri || row.lab?.path || "",
    method: transaction.request?.method || row.request?.method || row.http?.request?.method || "",
    request_headers: transaction.request?.headers || row.request?.headers || {},
    ip: row.source?.ip || row.client?.ip || row.request?.remote_ip || transaction.client_ip || "",
    status: row.http?.response?.status_code ?? row.status ?? transaction.response?.http_code ?? null,
    ...threat
  } };
}

function requestIdOf(raw) {
  const row = parseEmbeddedJson(raw);
  const transaction = row.transaction || row.audit_data?.transaction || {};
  const headers = transaction.request?.headers || row.request?.headers || {};
  const headerValue = Object.entries(headers).find(([key]) => key.toLowerCase() === "x-request-id")?.[1];
  const headerId = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  return row.http?.request?.id || headerId || row.lab?.request_id || "";
}

function overviewAlertOf(raw) {
  const row = normalizeLog(raw);
  const requestId = requestIdOf(raw);
  const portal = row.portal || {};
  if (!requestId || (!portal.category && !portal.blocked)) return null;
  return {
    request_id: requestId,
    at: row["@timestamp"] || null,
    method: portal.method || "",
    path: portal.path || "",
    category: portal.category || "WAF blocked request",
    severity: row.transaction?.messages?.[0]?.details?.severity || row.transaction?.messages?.[0]?.data?.severity || row.severity || row.log?.level || "unknown",
    rules: (portal.rules || []).slice(0, 8),
    status: portal.status,
    blocked: portal.blocked === true,
    source: portal.source_label || "WAF"
  };
}

async function attachHaproxyContext(rows, pit, elasticsearchUrl, fetchFn) {
  const ids = [...new Set(rows.filter(row => sourceOf(parseEmbeddedJson(row))[2] === "waf").map(requestIdOf).filter(Boolean))];
  if (!ids.length) return { items: correlateRows(rows, new Map()), pitId: pit };

  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: ids.length * 4, _source: compactLogSource, pit: { id: pit, keep_alive: PIT_KEEP_ALIVE },
      query: { bool: { filter: [{ term: { "input.type": "udp" } }, { bool: { should: [
        { terms: { "http.request.id": ids } }, ...ids.map(id => ({ match_phrase: { message: id } }))
      ], minimum_should_match: 1 } }] } } }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status} during correlation search`);
  const result = await response.json();
  const byId = new Map();
  for (const hit of result.hits?.hits || []) {
    const raw = parseEmbeddedJson(hit._source || {});
    const id = requestIdOf(raw);
    if (!id || byId.has(id) || raw.event?.dataset !== "haproxy.access") continue;
    byId.set(id, {
      request_id: id,
      client_ip: raw.source?.ip || "",
      method: raw.http?.request?.method || "",
      path: raw.url?.path || "",
      status: raw.http?.response?.status_code ?? null,
      route: raw.lab?.route || "",
      backend: raw.lab?.backend || "",
      server: raw.lab?.server || ""
    });
  }
  return { items: correlateRows(rows, byId), pitId: result.pit_id || pit };
}

function correlateRows(rows, byId) {
  return rows.map(raw => {
    const row = normalizeLog(raw);
    if (row.portal.source_group !== "waf") return row;
    const id = requestIdOf(raw);
    const haproxy = id && byId.get(id);
    return { ...row, portal: { ...row.portal, ...(haproxy ? { ip: haproxy.client_ip || row.portal.ip } : {}),
      correlation: { request_id: id || null, status: !id ? "missing_request_id" : haproxy ? "matched" : "not_found", haproxy: haproxy || null } } };
  });
}

async function attachDecisionContext(rows, pit, elasticsearchUrl, fetchFn) {
  const ids = [...new Set(rows.filter(row => [403, 429].includes(Number(row.portal?.status)) || row.portal?.blocked)
    .map(requestIdOf).filter(Boolean))];
  if (!ids.length) return { items: rows, pitId: pit };
  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: ids.length * 12, _source: compactLogSource, pit: { id: pit, keep_alive: PIT_KEEP_ALIVE },
      query: { bool: { should: ids.flatMap(id => [
        { match_phrase: { "http.request.id": id } },
        { match_phrase: { "transaction.request.headers.x-request-id": id } }
      ]), minimum_should_match: 1 } } }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status} during decision search`);
  const result = await response.json();
  const byId = new Map();
  for (const hit of result.hits?.hits || []) {
    const row = normalizeLog(hit._source || {});
    const id = requestIdOf(row);
    if (!ids.includes(id)) continue;
    const source = row.portal.block_source ||
      (row.portal.source_group === "finance" && row.event?.outcome === "application_rejected" ? "application" : null);
    if (!source) continue;
    const previous = byId.get(id);
    if (previous && !(source === "coraza" && previous.source !== "coraza")) continue;
    byId.set(id, { source, rule_id: row.portal.rules?.[0] || null, at: row["@timestamp"] || null });
  }
  return { items: rows.map(row => {
    const decision = byId.get(requestIdOf(row));
    return decision ? { ...row, portal: { ...row.portal,
      correlation: { ...(row.portal.correlation || {}), decision } } } : row;
  }), pitId: result.pit_id || pit };
}

function needsModeEvidence(row) {
  if (row.portal?.source_group === "waf") return true;
  return row.portal?.source_group === "haproxy" &&
    (row.lab?.route === "waf" || ["finance_waf_with_fallback", "finance_patched_waf"].includes(row.lab?.backend)) &&
    row.lab?.server !== "finance-fallback";
}

function propagateRequestModes(rows) {
  const modes = new Map(rows.filter(row => row.portal?.waf_mode && requestIdOf(row)).map(row => [requestIdOf(row),
    { value: row.portal.waf_mode, source: row.portal.waf_mode_source || row.portal.source_label || "log WAF" }]));
  return rows.map(row => {
    const mode = modes.get(requestIdOf(row));
    return needsModeEvidence(row) && !row.portal?.waf_mode && mode
      ? { ...row, portal: { ...row.portal, waf_mode: mode.value, waf_mode_source: mode.source } } : row;
  });
}

async function attachRequestMode(rows, pit, elasticsearchUrl, fetchFn) {
  const local = propagateRequestModes(rows);
  const ids = [...new Set(local.filter(row => needsModeEvidence(row) && !row.portal?.waf_mode)
    .map(requestIdOf).filter(Boolean))];
  if (!ids.length) return { items: local, pitId: pit };
  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: Math.min(ids.length * 4, 200),
      _source: { includes: ["@timestamp", "event.dataset", "log.file.path", "logger", "http.request.id",
        "transaction.request.headers", "request.headers", "lab.request_id", "lab.mode", "lab.waf_mode", "waf.policy.mode", "policy.mode"] },
      pit: { id: pit, keep_alive: PIT_KEEP_ALIVE },
      query: { bool: { filter: [wafSource, { bool: { should: ids.flatMap(id => [
        { match_phrase: { "http.request.id": id } },
        { match_phrase: { "transaction.request.headers.x-request-id": id } },
        { match_phrase: { "request.headers.x-request-id": id } },
        { match_phrase: { "lab.request_id": id } }
      ]), minimum_should_match: 1 } }] } } }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status} during request mode lookup`);
  const result = await response.json();
  const evidence = new Map();
  for (const hit of result.hits?.hits || []) {
    const raw = hit._source || {};
    const id = requestIdOf(raw);
    if (!ids.includes(id) || evidence.has(id)) continue;
    const row = normalizeLog(raw);
    if (row.portal.waf_mode) evidence.set(id, { value: row.portal.waf_mode, source: `${row.portal.source_label} cùng X-Request-ID` });
  }
  return { items: local.map(row => {
    const mode = evidence.get(requestIdOf(row));
    return needsModeEvidence(row) && !row.portal?.waf_mode && mode
      ? { ...row, portal: { ...row.portal, waf_mode: mode.value, waf_mode_source: mode.source } } : row;
  }), pitId: result.pit_id || pit };
}

async function attachModeHistory(rows, pit, elasticsearchUrl, fetchFn) {
  const missing = rows.filter(row => needsModeEvidence(row) && !row.portal?.waf_mode);
  const maxTime = missing.map(row => Date.parse(row["@timestamp"] || "")).filter(Number.isFinite).sort((a, b) => b - a)[0];
  if (!maxTime) return { items: rows, pitId: pit };
  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: 100, _source: { includes: ["@timestamp", "lab.mode"] },
      pit: { id: pit, keep_alive: PIT_KEEP_ALIVE }, sort: [{ "@timestamp": "desc" }],
      query: { bool: { filter: [{ term: { "event.dataset": "portal.audit" } }, { term: { "event.action": "policy_updated" } },
        { range: { "@timestamp": { lte: new Date(maxTime).toISOString() } } }] } } }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status} during WAF mode history search`);
  const result = await response.json();
  const history = (result.hits?.hits || []).map(hit => hit._source || {}).filter(row => ["On", "DetectionOnly", "Off"].includes(row.lab?.mode));
  return { items: rows.map(row => {
    if (row.portal?.waf_mode || !needsModeEvidence(row)) return row;
    const time = Date.parse(row["@timestamp"] || "");
    const prior = history.find(item => Date.parse(item["@timestamp"] || "") <= time);
    return prior ? { ...row, portal: { ...row.portal, waf_mode: prior.lab.mode, waf_mode_source: "portal.audit policy_updated theo thời gian" } } : row;
  }), pitId: result.pit_id || pit };
}

export async function fetchLogPage(params, elasticsearchUrl, fetchFn = fetch) {
  const { page, body, pitId, after } = logSearchRequest(params);
  let pit = pitId;
  if (!pit) {
    const opened = await fetchFn(`${elasticsearchUrl}/waf-lab-*/_pit?keep_alive=${PIT_KEEP_ALIVE}&allow_no_indices=true&ignore_unavailable=true`, {
      method: "POST", signal: AbortSignal.timeout(10000)
    });
    if (!opened.ok) throw new Error(`Elasticsearch PIT returned ${opened.status}`);
    pit = (await opened.json()).id;
    if (!pit) throw new Error("Elasticsearch did not return a PIT ID");
  }
  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...body, _source: compactLogSource, pit: { id: pit, keep_alive: PIT_KEEP_ALIVE }, ...(after ? { search_after: after } : {}) }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status}`);
  const result = await response.json();
  const total = result.hits?.total?.value || 0;
  const hits = result.hits?.hits || [];
  const pitLatest = result.pit_id || pit;
  const pageRows = hits.slice(0, LOG_PAGE_SIZE).map(hit => hit._source || {});
  const enriched = await attachHaproxyContext(pageRows, pitLatest, elasticsearchUrl, fetchFn);
  const decided = await attachDecisionContext(enriched.items, enriched.pitId, elasticsearchUrl, fetchFn);
  const requestMode = await attachRequestMode(decided.items, decided.pitId, elasticsearchUrl, fetchFn);
  const moded = await attachModeHistory(requestMode.items, requestMode.pitId, elasticsearchUrl, fetchFn);
  return { items: moded.items, total,
    page, page_size: LOG_PAGE_SIZE, pages: Math.max(1, Math.ceil(total / LOG_PAGE_SIZE)),
    pit_id: moded.pitId, next_after: hits.length > LOG_PAGE_SIZE ? hits[LOG_PAGE_SIZE - 1].sort : null };
}

const overviewSeverityFilters = {
  emergency: ["EMERGENCY", "EMERG", "0"],
  alert: ["ALERT", "1"],
  critical: ["CRITICAL", "2"],
  error: ["ERROR", "3"],
  warning: ["WARNING", "WARN", "4"],
  notice: ["NOTICE", "5"],
  info: ["INFO", "6"],
  debug: ["DEBUG", "7"]
};
const overviewCategoryKeys = ["cve", "sqli", "xss", "rce", "lfi", "ssrf", "bot", "rate_limit", "scanner", "behavior", "other", "unclassified"];
const severityFields = ["transaction.messages.details.severity", "transaction.messages.data.severity", "severity", "log.level", "severity_syslog"];
const severityFilter = values => {
  const candidates = [...new Set(values.flatMap(value => [value, String(value).toLowerCase()]))];
  return { bool: { should: severityFields.flatMap(field => [
    { terms: { [field]: candidates } }, { terms: { [`${field}.keyword`]: candidates } }
  ]), minimum_should_match: 1 } };
};
const exclusiveSeverityFilters = groups => {
  const result = {};
  const previous = [];
  for (const [key, values] of Object.entries(groups)) {
    const match = severityFilter(values);
    result[key] = previous.length ? { bool: { filter: [match], must_not: [...previous] } } : match;
    previous.push(match);
  }
  result.unknown = { bool: { must_not: previous } };
  return result;
};

function localMonthStart(now, offsetMinutes = 420) {
  const local = new Date(now.getTime() + offsetMinutes * 60000);
  return Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), 1) - offsetMinutes * 60000;
}

function localWeekStart(now, offsetMinutes = 420) {
  const local = new Date(now.getTime() + offsetMinutes * 60000);
  const start = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate());
  return start - ((local.getUTCDay() + 6) % 7) * 86400000 - offsetMinutes * 60000;
}

function suspiciousWafFilter() {
  return { bool: { should: [
    { term: { "transaction.is_interrupted": true } }, { term: { is_interrupted: true } },
    { wildcard: { "transaction.messages.details.tags": "*attack-*" } },
    { wildcard: { "transaction.messages.data.tags": "*attack-*" } },
    ...["transaction.messages.details.ruleId", "transaction.messages.details.id", "transaction.messages.data.id", "rule.id"]
      .map(field => ({ range: { [field]: { gte: 900000, lt: 950000 } } })),
    ...["transaction.messages.details.ruleId", "transaction.messages.details.id", "transaction.messages.data.id", "rule.id"]
      .map(field => ({ range: { [field]: { gte: 100000, lt: 101000 } } })),
    { terms: { "event.action": ["bot_detected", "bot_blocked", "rate_limited", "login_burst", "declared_fanout", "geo_block"] } },
    { term: { "event.dataset": "waf.behavior" } }
  ], minimum_should_match: 1 } };
}

export async function fetchOverviewTimeline(elasticsearchUrl, fetchFn = fetch, now = new Date()) {
  const monthStart = localMonthStart(now);
  const timelineStart = Math.min(monthStart, localWeekStart(now));
  const suspicious = suspiciousWafFilter();
  const severityFilters = exclusiveSeverityFilters(overviewSeverityFilters);
  const monthRange = { range: { "@timestamp": { gte: new Date(monthStart).toISOString(), lte: now.toISOString() } } };
  const body = {
    size: 0,
    track_total_hits: false,
    query: { bool: { must_not: hiddenHealthChecks, filter: [wafSource,
      { range: { "@timestamp": { gte: new Date(timelineStart).toISOString(), lte: now.toISOString() } } }, suspicious
    ] } },
    aggs: { month: { filter: monthRange, aggs: { categories: { filters: { filters: Object.fromEntries(overviewCategoryKeys.map(key => [key, categoryFilters[key]])) } } } }, hours: {
      date_histogram: { field: "@timestamp", fixed_interval: "1h", time_zone: "Asia/Ho_Chi_Minh",
        min_doc_count: 0, extended_bounds: { min: new Date(timelineStart).toISOString(), max: now.toISOString() } },
      aggs: { severities: { filters: { filters: severityFilters } } }
    } }
  };
  const aggregationRequest = fetchFn(`${elasticsearchUrl}/waf-lab-*/_search?allow_no_indices=true&ignore_unavailable=true`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000)
  });
  const alertRequest = fetchFn(`${elasticsearchUrl}/waf-lab-*/_search?allow_no_indices=true&ignore_unavailable=true`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: 100, track_total_hits: false, _source: compactLogSource,
      sort: [{ "@timestamp": { order: "desc", unmapped_type: "date" } }],
      query: { bool: { must_not: hiddenHealthChecks, filter: [wafSource,
        monthRange, suspicious
      ] } } }),
    signal: AbortSignal.timeout(10000)
  });
  const [aggregationOutcome, alertOutcome] = await Promise.allSettled([aggregationRequest, alertRequest]);
  const readOutcome = async (outcome, label) => {
    if (outcome.status === "rejected") return { data: null, error: `${label}: ${outcome.reason?.message || "request failed"}` };
    if (!outcome.value.ok) return { data: null, error: `${label}: HTTP ${outcome.value.status}` };
    try { return { data: await outcome.value.json(), error: null }; }
    catch { return { data: null, error: `${label}: invalid Elasticsearch response` }; }
  };
  const [aggregation, alertLookup] = await Promise.all([
    readOutcome(aggregationOutcome, "aggregation"), readOutcome(alertOutcome, "alerts")
  ]);
  if (!aggregation.data && !alertLookup.data) throw new Error(`${aggregation.error}; ${alertLookup.error}`);
  const result = aggregation.data;
  const buckets = result?.aggregations?.hours?.buckets || [];
  const alertResult = alertLookup.data;
  const seen = new Set();
  const alerts = (alertResult?.hits?.hits || []).map(hit => overviewAlertOf(hit._source || {})).filter(Boolean)
    .filter(alert => !seen.has(alert.request_id) && seen.add(alert.request_id)).slice(0, 50);
  return { generated_at: now.toISOString(), timezone: "Asia/Ho_Chi_Minh", stats_available: Boolean(result), alerts_available: Boolean(alertResult),
    stats_error: aggregation.error, alerts_error: alertLookup.error,
    total: result?.aggregations?.month?.doc_count ?? result?.hits?.total?.value ?? null,
    category_counts: Object.fromEntries(Object.entries(result?.aggregations?.month?.categories?.buckets || result?.aggregations?.categories?.buckets || {}).map(([key, value]) => [key, value.doc_count || 0])),
    buckets: buckets.map(bucket => ({ at: bucket.key_as_string, total: bucket.doc_count || 0,
      severity: Object.fromEntries(Object.entries(bucket.severities?.buckets || {}).map(([key, value]) => [key, value.doc_count || 0])) })), alerts };
}

export async function fetchRequestTrace(id, elasticsearchUrl, fetchFn = fetch) {
  if (typeof id !== "string" || !id.trim() || id.length > 200) throw new Error("invalid request ID");
  const requestId = id.trim();
  const fields = ["http.request.id", "transaction.request.headers.x-request-id",
    "request.headers.X-Request-Id", "request.headers.x-request-id", "lab.request_id", "message"];
  const response = await fetchFn(`${elasticsearchUrl}/waf-lab-*/_search?ignore_unavailable=true&allow_no_indices=true`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: 201, track_total_hits: true, _source: compactLogSource,
      sort: [{ "@timestamp": { order: "asc", unmapped_type: "date" } }],
      query: { bool: { should: fields.map(field => ({ match_phrase: { [field]: requestId } })), minimum_should_match: 1 } } }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status} during request trace`);
  const result = await response.json();
  const exact = (result.hits?.hits || []).map(hit => parseEmbeddedJson(hit._source || {}))
    .filter(row => requestIdOf(row) === requestId).slice(0, 200);
  const items = propagateRequestModes(exact.map(normalizeLog));
  const needsMode = items.some(row => needsModeEvidence(row) && !row.portal?.waf_mode);
  if (needsMode && items.length) {
    const time = items.map(row => Date.parse(row["@timestamp"] || "")).filter(Number.isFinite).sort((a, b) => a - b)[0];
    if (time) {
      const historyResponse = await fetchFn(`${elasticsearchUrl}/waf-lab-*/_search?ignore_unavailable=true&allow_no_indices=true`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ size: 1, sort: [{ "@timestamp": "desc" }], query: { bool: { filter: [
          { term: { "event.dataset": "portal.audit" } }, { term: { "event.action": "policy_updated" } },
          { range: { "@timestamp": { lte: new Date(time).toISOString() } } }
        ] } } }),
        signal: AbortSignal.timeout(10000)
      });
      if (historyResponse.ok) {
        const history = await historyResponse.json();
        const mode = history.hits?.hits?.[0]?._source?.lab?.mode;
        if (["On", "DetectionOnly", "Off"].includes(mode)) for (const row of items) {
          if (needsModeEvidence(row) && !row.portal.waf_mode) {
            row.portal.waf_mode = mode;
            row.portal.waf_mode_source = "portal.audit policy_updated theo thời gian";
          }
        }
      }
    }
  }
  return { request_id: requestId, items, truncated: (result.hits?.total?.value || 0) > 200 || (result.hits?.hits?.length || 0) > 200 };
}
