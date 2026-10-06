import { isIP } from "node:net";

export const LOG_PAGE_SIZE = 25;

const fileSources = {
  "waf-access.jsonl": ["waf.access", "WAF access", "waf"],
  "waf-policy.jsonl": ["waf.behavior", "WAF policy", "waf"],
  "coraza-audit.jsonl": ["coraza.audit", "Coraza audit", "waf"],
  "portal.jsonl": ["portal.audit", "Portal audit", "portal"]
};

const fileMatch = names => ({ bool: { should: names.map(name => ({ wildcard: { "log.file.path": `*${name}` } })), minimum_should_match: 1 } });
const wafSource = { bool: { should: [fileMatch(["waf-access.jsonl", "waf-policy.jsonl", "coraza-audit.jsonl"]), { term: { "event.dataset": "waf.behavior" } }, { term: { "event.dataset": "coraza.audit" } }, { prefix: { logger: "http.log.access" } }], minimum_should_match: 1 } };
const financeSource = { bool: { should: [{ wildcard: { "log.file.path": "*finance*.jsonl" } }, { term: { "event.dataset": "finance.lab" } }], minimum_should_match: 1 } };
const portalSource = { bool: { should: [fileMatch(["portal.jsonl"]), { term: { "event.dataset": "portal.audit" } }], minimum_should_match: 1 } };
const knownSources = [{ term: { "input.type": "udp" } }, wafSource, financeSource, portalSource];
const ruleFamily = (prefix, tag) => ({ bool: { should: [
  { range: { "transaction.messages.details.ruleId": { gte: Number(`${prefix}000`), lt: Number(`${Number(prefix) + 1}000`) } } },
  { range: { "rule.id": { gte: `${prefix}000`, lt: `${Number(prefix) + 1}000` } } },
  { match_phrase: { "transaction.messages.details.tags": tag } }
], minimum_should_match: 1 } });
const categoryFilters = {
  sqli: ruleFamily("942", "attack-sqli"), xss: ruleFamily("941", "attack-xss"), rce: ruleFamily("932", "attack-rce"), lfi: ruleFamily("930", "attack-lfi"),
  ssrf: { bool: { should: [{ terms: { "transaction.messages.details.ruleId": [934110, 934120] } }, { term: { "transaction.messages.details.tags": "attack-ssrf" } }], minimum_should_match: 1 } },
  cve: { bool: { should: [{ terms: { "transaction.messages.details.ruleId": [100010, 100011] } }, { terms: { "rule.id": ["100010", "100011"] } }, { match_phrase: { message: "CVE" } }, { match_phrase: { "transaction.messages.message": "CVE" } }], minimum_should_match: 1 } }
};

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
  const status = params.get("status") || "all";
  if (!["all", "2xx", "3xx", "4xx", "5xx", "403"].includes(status)) throw new Error("invalid HTTP status filter");
  const event = (params.get("event") || "").trim();
  const path = (params.get("path") || "").trim();
  const ip = (params.get("ip") || "").trim();
  if ([event, path, ip].some(value => value.length > 120)) throw new Error("log column filter is too long");
  if (ip && !isIP(ip)) throw new Error("IP filter requires a complete IPv4 or IPv6 address");
  const from = params.get("from") || "";
  const to = params.get("to") || "";
  for (const date of [from, to]) if (date && (Number.isNaN(Date.parse(date)) || date.length > 40)) throw new Error("invalid log date");
  const filter = [];
  if (from || to) filter.push({ range: { "@timestamp": { ...(from ? { gte: from } : {}), ...(to ? { lt: to } : {}) } } });
  if (source === "haproxy") filter.push(knownSources[0]);
  if (source === "waf") filter.push(wafSource);
  if (source === "finance") filter.push(financeSource);
  if (source === "portal") filter.push(portalSource);
  if (source === "other") filter.push({ bool: { must_not: knownSources } });
  if (category !== "all") filter.push(categoryFilters[category]);
  if (status !== "all") {
    const code = status === "403" ? { gte: 403, lt: 404 } : { gte: Number(status[0]) * 100, lt: (Number(status[0]) + 1) * 100 };
    const should = ["http.response.status_code", "status", "transaction.response.http_code"].map(field => ({ range: { [field]: code } }));
    // Older UDP records store the HAProxy JSON as analyzed text in message.
    should.push({ bool: { filter: [{ term: { "input.type": "udp" } }, { match: { message: "status_code" } },
      status === "403" ? { term: { message: "403" } } : { wildcard: { message: `${status[0]}??` } }] } });
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }
  if (event) filter.push({ multi_match: { query: event, fields: ["event.action", "message", "transaction.messages.message"], operator: "and" } });
  if (path) filter.push({ multi_match: { query: path, fields: ["url.path", "request.uri", "transaction.request.uri", "message"], operator: "and" } });
  if (ip) filter.push({ bool: { should: [...["source.ip", "client.ip", "request.remote_ip", "transaction.client_ip"].map(field => ({ term: { [field]: ip } })),
    { bool: { filter: [{ term: { "input.type": "udp" } }, { match_phrase: { message: ip } }] } }], minimum_should_match: 1 } });
  if (q) {
    const should = [
      { multi_match: { query: q, fields: ["message", "http.request.id", "url.path", "request.uri", "transaction.id", "transaction.messages.message", "transaction.messages.details.message", "transaction.messages.details.data", "transaction.messages.details.match"], operator: "and" } },
      { match_phrase: { "http.request.id": q } }, { match_phrase: { "transaction.id": q } },
      // Older Filebeat UDP events have only the escaped JSON envelope in `message`.
      { bool: { filter: [{ term: { "input.type": "udp" } }, { match_phrase: { message: q } }] } }
    ];
    if (/^[0-9a-fA-F:.]+$/.test(q)) should.push({ term: { "source.ip": q } });
    if (/^\d{5,7}$/.test(q)) should.push({ term: { "rule.id": q } }, { term: { "transaction.messages.details.ruleId": Number(q) } });
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }
  const must_not = [
    { term: { "url.path": "/healthz" } },
    { term: { "url.original": "/healthz" } },
    { term: { "http.request.path": "/healthz" } },
    { term: { "request.path": "/healthz" } },
    { term: { "request.uri": "/healthz" } },
    { term: { "request.uri.keyword": "/healthz" } },
    { term: { "transaction.request.uri": "/healthz" } },
    { term: { "transaction.request.uri.keyword": "/healthz" } },
    { match_phrase: { message: "/healthz" } }
  ];
  return { page, pitId, after, body: { size: LOG_PAGE_SIZE + 1, track_total_hits: true,
    sort: [{ "@timestamp": { order: "desc", unmapped_type: "date", format: "strict_date_optional_time_nanos" } }], query: { bool: { filter, must_not } } } };
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
  if (row.event?.dataset) return [row.event.dataset, row.event.dataset, "other"];
  if (filename) return [filename, filename, "other"];
  if (row.logger?.startsWith("http.log.access")) return ["waf.access", "WAF access", "waf"];
  return ["unknown", "Không rõ nguồn (thiếu metadata)", "other"];
}

function threatOf(row) {
  const transaction = row.transaction || row.audit_data?.transaction || {};
  const rawMessages = transaction.messages || row.messages || [];
  const messages = Array.isArray(rawMessages) ? rawMessages : [];
  const rules = [row.rule?.id, ...messages.map(item => item.details?.ruleId || item.ruleId)].filter(Boolean).map(String);
  const matches = [...new Set(messages.map(item => item.details?.match || item.details?.data || item.match || item.data).filter(Boolean).map(value => String(value).slice(0, 240)))].slice(0, 3);
  const tags = messages.flatMap(item => item.details?.tags || item.tags || []).map(String);
  const description = [row.message, ...messages.map(item => item.message || item.details?.message)].filter(Boolean).join(" ");
  const labCves = { "100010": "CVE-2026-64642", "100011": "CVE-2026-64645" };
  const cves = [...new Set([...(description.match(/CVE-\d{4}-\d{4,}/gi) || []).map(value => value.toUpperCase()), ...rules.map(rule => labCves[rule]).filter(Boolean)])];
  const tagText = tags.join(" ").toLowerCase();
  const hasRule = prefix => rules.some(rule => rule.startsWith(prefix));
  let category = null;
  if (cves.length) category = cves.join(", ");
  else if (tagText.includes("attack-sqli") || hasRule("942")) category = "SQL injection";
  else if (tagText.includes("attack-xss") || hasRule("941")) category = "XSS";
  else if (tagText.includes("attack-rce") || hasRule("932")) category = "Command injection / RCE";
  else if (tagText.includes("attack-lfi") || hasRule("930")) category = "Path traversal / LFI";
  else if (tagText.includes("attack-ssrf") || rules.some(rule => ["934110", "934120"].includes(rule))) category = "SSRF";
  else if (hasRule("934")) category = "Generic application attack";
  else if (tagText.includes("attack-protocol") || hasRule("920")) category = "HTTP protocol";
  else if (tagText.includes("attack-scanner") || hasRule("913")) category = "Scanner";
  return { category, cves, rules: [...new Set(rules)], matches };
}

export function normalizeLog(raw) {
  const row = parseEmbeddedJson(raw);
  const transaction = row.transaction || row.audit_data?.transaction || {};
  const [dataset, label, group] = sourceOf(row);
  const threat = threatOf(row);
  return { ...row, portal: {
    source: dataset, source_label: label, source_group: group,
    explanation: explainEvent(row),
    path: row.url?.path || row.request?.uri || transaction.request?.uri || row.lab?.path || "",
    ip: row.source?.ip || row.client?.ip || row.request?.remote_ip || transaction.client_ip || "",
    status: row.http?.response?.status_code ?? row.status ?? transaction.response?.http_code ?? null,
    ...threat
  } };
}

function requestIdOf(raw) {
  const row = parseEmbeddedJson(raw);
  return row.http?.request?.id || row.transaction?.id || row.audit_data?.transaction?.id || "";
}

async function attachHaproxyContext(rows, pit, elasticsearchUrl, fetchFn) {
  const ids = [...new Set(rows.filter(row => sourceOf(parseEmbeddedJson(row))[2] === "waf").map(requestIdOf).filter(Boolean))];
  if (!ids.length) return { items: correlateRows(rows, new Map()), pitId: pit };

  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: ids.length * 4, pit: { id: pit, keep_alive: "5m" },
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

export async function fetchLogPage(params, elasticsearchUrl, fetchFn = fetch) {
  const { page, body, pitId, after } = logSearchRequest(params);
  let pit = pitId;
  if (!pit) {
    const opened = await fetchFn(`${elasticsearchUrl}/waf-lab-*/_pit?keep_alive=5m&allow_no_indices=true&ignore_unavailable=true`, {
      method: "POST", signal: AbortSignal.timeout(10000)
    });
    if (!opened.ok) throw new Error(`Elasticsearch PIT returned ${opened.status}`);
    pit = (await opened.json()).id;
    if (!pit) throw new Error("Elasticsearch did not return a PIT ID");
  }
  const response = await fetchFn(`${elasticsearchUrl}/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...body, pit: { id: pit, keep_alive: "5m" }, ...(after ? { search_after: after } : {}) }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Elasticsearch returned ${response.status}`);
  const result = await response.json();
  const total = result.hits?.total?.value || 0;
  const hits = result.hits?.hits || [];
  const pitLatest = result.pit_id || pit;
  const pageRows = hits.slice(0, LOG_PAGE_SIZE).map(hit => hit._source || {});
  const enriched = await attachHaproxyContext(pageRows, pitLatest, elasticsearchUrl, fetchFn);
  return { items: enriched.items, total,
    page, page_size: LOG_PAGE_SIZE, pages: Math.max(1, Math.ceil(total / LOG_PAGE_SIZE)),
    pit_id: enriched.pitId, next_after: hits.length > LOG_PAGE_SIZE ? hits[LOG_PAGE_SIZE - 1].sort : null };
}
