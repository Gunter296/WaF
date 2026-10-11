import test from "node:test";
import assert from "node:assert/strict";
import { fetchLogPage, fetchOverviewTimeline, logSearchRequest, normalizeLog } from "./logs.mjs";

const hasClause = (value, predicate) => predicate(value) || (value && typeof value === "object" && Object.values(value).some(child => Array.isArray(child)
  ? child.some(item => hasClause(item, predicate)) : hasClause(child, predicate)));

test("event categories require identifying rules or event metadata and body evidence is narrow", () => {
  assert.equal(normalizeLog({ event: { dataset: "waf.behavior", action: "block" }, rule: { id: "bot_declared_fanout" } }).portal.category_key, "bot");
  assert.equal(normalizeLog({ event: { dataset: "coraza.audit" }, transaction: { messages: [{ details: { ruleId: 913100 } }] } }).portal.category_key, "scanner");
  assert.equal(normalizeLog({ event: { dataset: "waf.behavior" }, rule: { id: "rate_limit" } }).portal.category_key, "rate_limit");
  assert.equal(normalizeLog({ http: { response: { status_code: 403 } } }).portal.category_key, "unclassified");
  const queryArg = normalizeLog({ transaction: { messages: [{ details: { ruleId: 942100, data: "Matched Data: x found within ARGS:q" } }] } });
  assert.deepEqual(queryArg.portal.body_evidence, []);
  const bodyArg = normalizeLog({ transaction: { messages: [{ details: { ruleId: 942100, data: "Matched Data: x found within REQUEST_BODY:payload" } }] } });
  assert.equal(bodyArg.portal.body_evidence[0].variable, "REQUEST_BODY:payload");
});

test("preserves structured policy counters and distinguishes threshold from a real block", () => {
  const blocked = normalizeLog({
    event: { dataset: "waf.behavior", kind: "blocked", action: "block" },
    http: { request: { id: "req-counter-1" }, response: { status_code: 429 } },
    rule: { id: "rate_limit" },
    waf: { policy: { mode: "On", counter_type: "requests_per_ip", count: 31, limit: 30, window_seconds: 10, configured_action: "block", decision_result: "blocked", actual_block: true } }
  });
  assert.equal(blocked.portal.policy_evidence.count, 31);
  assert.equal(blocked.portal.waf_mode, "On");
  assert.equal(blocked.portal.blocked, true);
  assert.equal(blocked.portal.block_source, "waf_policy");
  const threshold = normalizeLog({
    event: { dataset: "waf.behavior", kind: "behavior", action: "block" },
    http: { request: { id: "req-counter-2" }, response: { status_code: 404 } },
    rule: { id: "not_found_burst" },
    waf: { policy: { count: 15, limit: 15, decision_result: "threshold_reached", actual_block: false } }
  });
  assert.equal(threshold.portal.policy_evidence.count, 15);
  assert.equal(threshold.portal.blocked, false);
  assert.equal(threshold.portal.block_source, null);
});

test("old HAProxy JSON in message is decoded without duplicating the escaped envelope", () => {
  const raw = { "@timestamp": "2026-10-06T03:00:00Z", input: { type: "udp" }, message: JSON.stringify({ event: { dataset: "haproxy.access" }, source: { ip: "172.22.0.1" }, url: { path: "/api/lab/search" }, http: { response: { status_code: 403 } } }) };
  const row = normalizeLog(raw);
  assert.equal(row.portal.source_label, "HAProxy access");
  assert.equal(row.portal.ip, "172.22.0.1");
  assert.equal(row.portal.status, 403);
  assert.equal(row.message, undefined);
  assert.equal(row.event.dataset, "haproxy.access");
});

test("HAProxy lifecycle and malformed-request events get plain-language explanations", () => {
  const stopped = normalizeLog({ input: { type: "udp" }, message: "Proxy lab_http stopped (cumulated conns: FE: 0, BE: 0)." });
  assert.equal(stopped.portal.explanation, "Proxy “lab_http” đã dừng. HAProxy ghi nhận 0 kết nối đi vào (FE) và 0 kết nối tới backend (BE). Đây là thông báo trạng thái, không phải một yêu cầu bị chặn.");
  const badRequest = normalizeLog({ input: { type: "udp" }, message: JSON.stringify({ http: { request: { method: "<BADREQ>" }, response: { status_code: 400 } }, source: { ip: "172.22.0.1" }, url: { path: "<BADREQ>" } }) });
  assert.match(badRequest.portal.explanation, /dữ liệu không đúng định dạng HTTP/);
  assert.equal(badRequest.portal.status, 400);
  const health = normalizeLog({ input: { type: "udp" }, message: "Server finance_waf_with_fallback/waf is DOWN, reason: Layer4 timeout" });
  assert.equal(health.portal.explanation, "WAF down");
});

test("Caddy file and Coraza audit have explicit sources and rule classification", () => {
  const access = normalizeLog({ log: { file: { path: "/var/log/lab/waf-access.jsonl" } }, request: { uri: "/account" }, status: 403 });
  assert.equal(access.portal.source_label, "WAF access");
  const audit = normalizeLog({ log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { messages: [
    { message: "SQL Injection Attack", details: { ruleId: 942100, tags: ["attack-sqli"] } },
    { message: "WAF lab virtual patch CVE-2026-64642", details: { ruleId: 100010 } }
  ] } });
  assert.equal(audit.portal.source_label, "Coraza audit");
  assert.equal(audit.portal.category, "CVE-2026-64642");
  assert.deepEqual(audit.portal.rules, ["942100", "100010"]);
  assert.equal(normalizeLog({ rule: { id: 100011 } }).portal.category, "CVE-2026-64645");
  const sqli = normalizeLog({ transaction: { messages: [{ details: { ruleId: 942100, tags: ["attack-sqli"], match: "Matched ARGS:q" } }] } });
  assert.equal(sqli.portal.category, "SQL injection");
  assert.deepEqual(sqli.portal.matches, ["Matched ARGS:q"]);
  const payload = normalizeLog({ transaction: { messages: [{ details: { ruleId: 942100, data: "Matched Data: ' OR 1=1-- found within ARGS:q" } }] } });
  assert.deepEqual(payload.portal.matches, ["Matched Data: ' OR 1=1-- found within ARGS:q"]);
});

test("Coraza audit schema classifies CRS SQLi and formats matched data without object coercion", () => {
  const row = normalizeLog({
    log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } },
    transaction: { is_interrupted: true, id: "BXlmEarWWqJFLOTQ", request: { uri: "/api/lab/search?q=%27%20OR%201%3D1--" }, messages: [
      { message: "SQL Injection Attack Detected via libinjection", data: { id: 942100, tags: ["attack-sqli", "OWASP_CRS"], data: "Matched Data: s&1c found within ARGS:q: ' OR 1=1--" } },
      { message: "Inbound Anomaly Score Exceeded (Total Score: 5)", data: { id: 949110, tags: ["anomaly-evaluation"] } }
    ] }
  });
  assert.equal(row.portal.category, "SQL injection");
  assert.deepEqual(row.portal.rules, ["942100", "949110"]);
  assert.equal(row.portal.matches[0], "Matched Data: s&1c found within ARGS:q: ' OR 1=1--");
  assert.equal(row.portal.blocked, true);
});

test("unrecognized file keeps its filename as source instead of a generic label", () => {
  const row = normalizeLog({ log: { file: { path: "/var/log/nuclei/probe.jsonl" } } });
  assert.equal(row.portal.source_label, "probe.jsonl");
});

test("pagination and every selected filter reach Elasticsearch as conjunctive, field-specific clauses", () => {
  const { page, body, pitId, after } = logSearchRequest(new URLSearchParams({ page: "3", pit: "validPIT123=", after: '["2026-10-06T04:00:00.000Z",123]', source: "waf", from: "2026-10-05T17:00:00.000Z", to: "2026-10-06T17:00:00.000Z", q: "942100", category: "sqli", status: "403", event: "request", path: "/api/lab/search", ip: "192.0.2.10" }));
  assert.equal(page, 3);
  assert.equal(body.size, 26);
  assert.equal(body.from, undefined);
  assert.equal(pitId, "validPIT123=");
  assert.deepEqual(after, ["2026-10-06T04:00:00.000Z", 123]);
  assert.equal(body.track_total_hits, true);
  assert.ok(body.query.bool.filter.some(item => item.range?.["@timestamp"]));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.multi_match?.query === "942100")));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.multi_match?.fields?.includes("transaction.messages.details.data"))));
  assert.ok(hasClause(body.query.bool.filter, part => part.range?.["transaction.messages.details.ruleId"]?.gte === 942000));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.range?.["http.response.status_code"]?.gte === 403)));
  assert.ok(!hasClause(body.query.bool.filter, part => part.term?.message === "403"));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.term?.["source.ip"] === "192.0.2.10")));
  assert.ok(!hasClause(body.query.bool.filter, part => part.match_phrase?.message === "192.0.2.10"));
  assert.ok(body.query.bool.filter.some(item => item.multi_match?.fields?.join(",") === "event.action,event.dataset"));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.match_phrase?.["transaction.request.uri"] === "/api/lab/search")));
  assert.equal(body.query.bool.filter.length, 8, "date/source/category/status/event/path/IP/general search are ANDed");
  assert.ok(body.query.bool.must_not.some(item => item.term?.["url.path"] === "/healthz"));
  assert.ok(body.query.bool.must_not.some(item => item.match_phrase?.message === "/healthz"));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.prefix?.logger === "http.log.access")));
  assert.throws(() => logSearchRequest(new URLSearchParams({ ip: "192.0" })), /complete IPv4 or IPv6/);
  assert.throws(() => logSearchRequest(new URLSearchParams({ page: "2" })), /missing log cursor/);
});

test("each filter is independently translated and does not match absent fields via free-form message", () => {
  const cases = [
    ["q", "req-77", item => item.bool?.should?.some(clause => clause.match_phrase?.["http.request.id"] === "req-77")],
    ["from", "2026-10-01T00:00:00Z", item => item.range?.["@timestamp"]?.gte === "2026-10-01T00:00:00Z"],
    ["source", "portal", item => hasClause(item, clause => clause.term?.["event.dataset"] === "portal.audit")],
    ["event", "policy_updated", item => item.multi_match?.fields?.includes("event.action")],
    ["category", "bot", item => hasClause(item, clause => clause.terms?.["rule.id"]?.includes?.("bot_declared_fanout"))],
    ["path", "/account", item => item.bool?.should?.some(clause => clause.match_phrase?.["request.uri"] === "/account")],
    ["ip", "192.0.2.77", item => item.bool?.should?.some(clause => clause.term?.["source.ip"] === "192.0.2.77")],
    ["status", "5xx", item => item.bool?.should?.some(clause => clause.range?.["http.response.status_code"]?.gte === 500)]
  ];
  for (const [key, value, predicate] of cases) {
    const { body } = logSearchRequest(new URLSearchParams({ [key]: value }));
    assert.ok(body.query.bool.filter.some(predicate), `${key} filter clause exists`);
    if (["event", "path", "ip", "status"].includes(key)) {
      assert.equal(hasClause(body.query.bool.filter, clause => clause.match_phrase?.message === value || clause.term?.message === value), false,
        `${key} does not create matches from an unrelated message`);
    }
  }
});

test("minute precision time range reaches Elasticsearch with an exclusive end", () => {
  const from = "2026-10-10T03:15:00.000Z";
  const to = "2026-10-10T04:25:00.000Z";
  const { body } = logSearchRequest(new URLSearchParams({ from, to }));
  assert.deepEqual(body.query.bool.filter[0].range["@timestamp"], { gte: from, lt: to });
  assert.throws(() => logSearchRequest(new URLSearchParams({ from: to, to: from })), /end time/);
  assert.throws(() => logSearchRequest(new URLSearchParams({ from: "2026-10-10" })), /invalid log date/);
});

test("overview categories use the same log filters and return counts", async () => {
  const calls = [];
  const fakeFetch = async (_url, options) => {
    const body = JSON.parse(options.body);
    calls.push(body);
    if (body.aggs) return { ok: true, json: async () => ({ hits: { total: { value: 4 } }, aggregations: {
      hours: { buckets: [] }, categories: { buckets: { sqli: { doc_count: 3 }, scanner: { doc_count: 1 } } }
    } }) };
    return { ok: true, json: async () => ({ hits: { hits: [] } }) };
  };
  const overview = await fetchOverviewTimeline("http://elasticsearch:9200", fakeFetch, new Date("2026-10-10T10:00:00Z"));
  assert.deepEqual(overview.category_counts, { sqli: 3, scanner: 1 });
  assert.ok(calls[0].aggs.categories.filters.filters.sqli);
  assert.ok(calls[0].aggs.categories.filters.filters.scanner);
  assert.ok(calls[1]._source.excludes.includes("transaction.response.body"));
});

test("every source and event type option has a server-side query; DDoS is not inferred", () => {
  for (const source of ["haproxy", "waf", "finance", "portal", "other"]) {
    const { body } = logSearchRequest(new URLSearchParams({ source }));
    assert.ok(body.query.bool.filter.length > 0, `${source} has a filter`);
  }
  for (const category of ["sqli", "xss", "rce", "lfi", "ssrf", "cve", "bot", "scanner", "behavior", "rate_limit", "other", "unclassified"]) {
    const { body } = logSearchRequest(new URLSearchParams({ category }));
    assert.equal(body.query.bool.filter.length, 1, `${category} maps to a category predicate`);
  }
  assert.throws(() => logSearchRequest(new URLSearchParams({ category: "ddos" })), /invalid log category/);
});

test("PIT cursor reaches the next page without the 10,000-result offset window", async () => {
  const calls = [];
  const fakeFetch = async (url, options) => {
    calls.push({ url, body: options.body ? JSON.parse(options.body) : null });
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    const secondPage = Boolean(JSON.parse(options.body).search_after);
    const hits = (secondPage ? [26] : Array.from({ length: 26 }, (_, index) => index + 1)).map(index => ({
      _source: { "@timestamp": "2026-10-06T04:00:00.000Z", input: { type: "udp" }, event: { dataset: "haproxy.access" } },
      sort: ["2026-10-06T04:00:00.000Z", index]
    }));
    return { ok: true, json: async () => ({ pit_id: secondPage ? "pit-latest" : "pit-next", hits: { total: { value: 10001 }, hits } }) };
  };
  const first = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.equal(first.items.length, 25);
  assert.deepEqual(first.next_after, ["2026-10-06T04:00:00.000Z", 25]);
  assert.equal(first.pages, 401);
  const second = await fetchLogPage(new URLSearchParams({ page: "2", pit: first.pit_id, after: JSON.stringify(first.next_after) }), "http://elasticsearch:9200", fakeFetch);
  assert.equal(second.page, 2);
  assert.equal(second.items.length, 1);
  assert.equal(second.next_after, null);
  assert.equal(calls.filter(call => call.url.includes("/_pit?")).length, 1);
  const pageTwo = calls.find(call => call.body?.search_after);
  assert.deepEqual(pageTwo.body.search_after, first.next_after);
  assert.equal(pageTwo.body.from, undefined);
});

test("WAF JSON includes selected HAProxy context matched by request ID", async () => {
  const calls = [];
  const fakeFetch = async (url, options) => {
    calls.push({ url, body: options.body ? JSON.parse(options.body) : null });
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    const query = JSON.parse(options.body);
    if (query.query?.bool?.filter?.some(item => item.term?.["input.type"] === "udp")) {
      return { ok: true, json: async () => ({ pit_id: "pit-correlated", hits: { hits: [{ _source: { input: { type: "udp" }, message: JSON.stringify({
        event: { dataset: "haproxy.access" }, http: { request: { id: "req-42", method: "POST" }, response: { status_code: 403 } },
        source: { ip: "192.0.2.42" }, url: { path: "/api/lab/search" }, lab: { route: "waf", backend: "finance_waf_with_fallback", server: "waf" }
      }) } }] } }) };
    }
    return { ok: true, json: async () => ({ hits: { total: { value: 1 }, hits: [{
      _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "coraza-tx-42", request: { headers: { "X-Request-ID": ["req-42"], "x-lab-mode": ["On"] } }, messages: [{ message: "SQL Injection Attack", details: { ruleId: 942100 } }] } },
      sort: ["2026-10-06T04:00:00.000Z", 1]
    }] } }) };
  };
  const result = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.equal(result.items[0].portal.category, "SQL injection");
  assert.equal(result.pit_id, "pit-correlated");
  assert.equal(result.items[0].portal.ip, "192.0.2.42");
  assert.deepEqual(result.items[0].portal.correlation, { request_id: "req-42", status: "matched", haproxy: {
    request_id: "req-42", client_ip: "192.0.2.42", method: "POST", path: "/api/lab/search", status: 403,
    route: "waf", backend: "finance_waf_with_fallback", server: "waf"
  } });
  assert.equal(calls.filter(call => call.url.endsWith("/_search")).length, 2);
});

test("WAF access without mode joins Coraza audit by request ID across pages", async () => {
  const calls = [];
  const fakeFetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push(body);
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-mode-join" }) };
    if (body?._source?.includes?.includes("transaction.request.headers")) return { ok: true, json: async () => ({ hits: { hits: [{ _source: {
      event: { dataset: "coraza.audit" }, transaction: { request: { headers: { "x-request-id": ["req-mode-42"], "x-lab-mode": ["DetectionOnly"] } } }
    } }] } }) };
    if (body?.query?.bool?.filter?.some(item => item.term?.["input.type"] === "udp")) return { ok: true, json: async () => ({ hits: { hits: [] } }) };
    return { ok: true, json: async () => ({ hits: { total: { value: 1 }, hits: [{
      _source: { "@timestamp": "2026-10-10T04:00:00Z", log: { file: { path: "/var/log/lab/waf-access.jsonl" } },
        http: { request: { id: "req-mode-42" } }, request: { uri: "/dashboard" }, status: 200 },
      sort: ["2026-10-10T04:00:00Z", 1]
    }] } }) };
  };
  const result = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.equal(result.items[0].portal.waf_mode, "DetectionOnly");
  assert.match(result.items[0].portal.waf_mode_source, /Coraza audit cùng X-Request-ID/);
  assert.equal(calls.some(body => body?.query?.bool?.filter?.some(item => item.term?.["event.dataset"] === "portal.audit")), false);
});

test("WAF JSON identifies a missing HAProxy match and a missing request ID", async () => {
  const fakeFetch = async url => {
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    return { ok: true, json: async () => ({ hits: { total: { value: 2 }, hits: [
      { _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "coraza-unmatched", request: { headers: { "x-request-id": ["req-unmatched"] } } } }, sort: ["2026-10-06T04:00:00.000Z", 1] },
      { _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: {} }, sort: ["2026-10-06T03:00:00.000Z", 2] }
    ] } }) };
  };
  const result = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.deepEqual(result.items.map(row => row.portal.correlation), [
    { request_id: "req-unmatched", status: "not_found", haproxy: null },
    { request_id: null, status: "missing_request_id", haproxy: null }
  ]);
});

test("historical WAF mode comes from the latest earlier policy audit", async () => {
  const calls = [];
  const fakeFetch = async (url, options) => {
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ url, body });
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-mode" }) };
    if (body?.query?.bool?.filter?.some(item => item.term?.["input.type"] === "udp")) return { ok: true, json: async () => ({ hits: { hits: [] } }) };
    if (body?.query?.bool?.filter?.some(item => item.term?.["event.dataset"] === "portal.audit")) return { ok: true, json: async () => ({ hits: { hits: [
      { _source: { "@timestamp": "2026-10-06T03:59:00Z", event: { dataset: "portal.audit", action: "policy_updated" }, lab: { mode: "DetectionOnly" } } }
    ] } }) };
    return { ok: true, json: async () => ({ hits: { total: { value: 1 }, hits: [{
      _source: { "@timestamp": "2026-10-06T04:00:00Z", log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "internal-1", request: { headers: { "X-Request-ID": ["request-1"] } } } },
      sort: ["2026-10-06T04:00:00Z", 1]
    }] } }) };
  };
  const result = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.equal(result.items[0].portal.waf_mode, "DetectionOnly");
  assert.match(result.items[0].portal.waf_mode_source, /portal.audit/);
  const historyQuery = calls.find(call => call.body?.query?.bool?.filter?.some(item => item.term?.["event.dataset"] === "portal.audit"));
  assert.equal(historyQuery.body.query.bool.filter.some(item => item.range?.["@timestamp"]?.lte === "2026-10-06T04:00:00.000Z"), true);
});

test("expired PIT during HAProxy correlation uses the standard 404 signal", async () => {
  let searches = 0;
  const fakeFetch = async url => {
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    searches++;
    if (searches === 1) return { ok: true, json: async () => ({ hits: { total: { value: 1 }, hits: [{
      _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "internal-expired", request: { headers: { "X-Request-ID": ["req-expired"] } } } },
      sort: ["2026-10-06T04:00:00.000Z", 1]
    }] } }) };
    return { ok: false, status: 404 };
  };
  await assert.rejects(fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch), /Elasticsearch returned 404/);
});
