import test from "node:test";
import assert from "node:assert/strict";
import { fetchLogPage, logSearchRequest, normalizeLog } from "./logs.mjs";

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

test("unrecognized file keeps its filename as source instead of a generic label", () => {
  const row = normalizeLog({ log: { file: { path: "/var/log/nuclei/probe.jsonl" } } });
  assert.equal(row.portal.source_label, "probe.jsonl");
});

test("pagination and per-column filters are sent to Elasticsearch, not applied to one page", () => {
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
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.range?.["transaction.messages.details.ruleId"]?.gte === 942000)));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.range?.["http.response.status_code"]?.gte === 403)));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.bool?.filter?.some(clause => clause.term?.message === "403"))));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.term?.["source.ip"] === "192.0.2.10")));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.bool?.filter?.some(clause => clause.match_phrase?.message === "942100"))));
  assert.ok(body.query.bool.must_not.some(item => item.term?.["url.path"] === "/healthz"));
  assert.ok(body.query.bool.must_not.some(item => item.match_phrase?.message === "/healthz"));
  assert.ok(body.query.bool.filter.some(item => item.bool?.should?.some(part => part.prefix?.logger === "http.log.access")));
  assert.throws(() => logSearchRequest(new URLSearchParams({ ip: "192.0" })), /complete IPv4 or IPv6/);
  assert.throws(() => logSearchRequest(new URLSearchParams({ page: "2" })), /missing log cursor/);
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
  assert.deepEqual(calls.at(-1).body.search_after, first.next_after);
  assert.equal(calls.at(-1).body.from, undefined);
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
      _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "req-42", messages: [{ message: "SQL Injection Attack", details: { ruleId: 942100 } }] } },
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

test("WAF JSON identifies a missing HAProxy match and a missing request ID", async () => {
  const fakeFetch = async url => {
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    return { ok: true, json: async () => ({ hits: { total: { value: 2 }, hits: [
      { _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "req-unmatched" } }, sort: ["2026-10-06T04:00:00.000Z", 1] },
      { _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: {} }, sort: ["2026-10-06T03:00:00.000Z", 2] }
    ] } }) };
  };
  const result = await fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch);
  assert.deepEqual(result.items.map(row => row.portal.correlation), [
    { request_id: "req-unmatched", status: "not_found", haproxy: null },
    { request_id: null, status: "missing_request_id", haproxy: null }
  ]);
});

test("expired PIT during HAProxy correlation uses the standard 404 signal", async () => {
  let searches = 0;
  const fakeFetch = async url => {
    if (url.includes("/_pit?")) return { ok: true, json: async () => ({ id: "pit-start" }) };
    searches++;
    if (searches === 1) return { ok: true, json: async () => ({ hits: { total: { value: 1 }, hits: [{
      _source: { log: { file: { path: "/var/log/lab/coraza-audit.jsonl" } }, transaction: { id: "req-expired" } },
      sort: ["2026-10-06T04:00:00.000Z", 1]
    }] } }) };
    return { ok: false, status: 404 };
  };
  await assert.rejects(fetchLogPage(new URLSearchParams(), "http://elasticsearch:9200", fakeFetch), /Elasticsearch returned 404/);
});
