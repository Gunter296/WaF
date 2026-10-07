import test from "node:test";
import assert from "node:assert/strict";
import { extractCandidates, ratesFromBuckets, toSyslogSeverity } from "./learning.mjs";

test("groups Coraza events by rule, PL, method, path and parameter", () => {
  const source = { "@timestamp": "2026-09-29T01:00:00Z", transaction: { id: "request-1", request: { method: "GET", uri: "/api/lab/search?q=test" },
    messages: [{ details: { ruleId: 942100, tags: ["paranoia-level/2"], match: "Matched ARGS:q", severity: "Warning" } }] } };
  const [group] = extractCandidates([source, { ...source, "@timestamp": "2026-09-28T01:00:00Z", transaction: { ...source.transaction, id: "request-2" } }], 1);
  assert.equal(group.count, 2);
  assert.equal(group.days, 2);
  assert.equal(group.estimated_blocks, 2);
  assert.equal(group.parameter, "ARGS:q");
  assert.equal(group.site, "finance-vulnerable");
  assert.equal(group.severity_syslog, 4);
  assert.equal(group.severity_source, "warning");
});

test("counts each request ID once per rule and parameter", () => {
  const source = { "@timestamp": "2026-09-29T01:00:00Z", transaction: { id: "same-request", request: { method: "GET", uri: "/api/lab/search" } },
    messages: [{ details: { ruleId: 942100, tags: ["paranoia-level/2"], match: "Matched ARGS:q" } },
      { details: { ruleId: 942100, tags: ["paranoia-level/2"], match: "Matched ARGS:q" } }] };
  assert.equal(extractCandidates([source], 1)[0].count, 1);
});

test("reads Coraza v3.7 top-level messages", () => {
  const source = { "@timestamp": "2026-09-29T01:00:00Z", transaction: { id: "request-2", request: { method: "POST", uri: "/api/lab/search" } },
    messages: [{ details: { ruleId: "942100", tags: ["paranoia-level/1"], match: "Matched ARGS:q", severity: "2" } }] };
  const [group] = extractCandidates([source], 1);
  assert.equal(group.rule_id, 942100);
  assert.equal(group.severity, "2");
  assert.equal(group.severity_syslog, 2);
});

test("preserves the original numeric severity for the portal label", () => {
  const source = { "@timestamp": "2026-10-07T06:40:00Z", transaction: { id: "warning-request", request: {
    method: "GET", uri: "/api/lab/search?q=normal", headers: { host: ["localhost"] }
  } }, messages: [{ data: { id: 942100, severity: 4, tags: ["paranoia-level/1"], raw: "Matched ARGS:q" } }] };
  const [group] = extractCandidates([source], 1);
  assert.equal(group.severity, "4");
  assert.equal(group.severity_syslog, 4);
  assert.equal(group.severity_source, "4");
});

test("reads Coraza JSON audit data.id and preserves X-Request-ID correlation", () => {
  const requestId = "AC1E000A:1234_AC1E0002:1F90_6AC5E9ED_0001";
  const source = { "@timestamp": "2026-10-07T06:40:00Z", transaction: { id: "coraza-transaction-id", request: {
    method: "GET", uri: "/api/lab/search?q=test", headers: { host: ["localhost"], "x-request-id": [requestId] }
  } }, messages: [{ message: "SQL Injection Attack", data: { id: 942100, severity: 2, tags: ["paranoia-level/1"],
    raw: "Matched REQUEST_HEADERS:User-Agent and ARGS:q" } }] };
  const [group] = extractCandidates([source], 1);
  assert.equal(group.rule_id, 942100);
  assert.equal(group.parameter, "ARGS:q");
  assert.equal(group.sample_request_ids[0], requestId);
  assert.equal(group.severity, "2");
  assert.equal(group.severity_syslog, 2);
});

test("does not propose CRS anomaly score aggregator rules", () => {
  const source = { "@timestamp": "2026-10-07T06:40:00Z", transaction: { id: "coraza-transaction-id", request: {
    method: "GET", uri: "/api/lab/search?q=test", headers: { host: ["localhost"] }
  } }, messages: [{ message: "Inbound Anomaly Score Exceeded", data: { id: 949110, tags: ["anomaly-evaluation"] } }] };
  assert.deepEqual(extractCandidates([source], 1), []);
});

test("rejects negative values as outside the Syslog severity scale", () => {
  assert.equal(toSyslogSeverity(-1), null);
});

test("maps all Syslog severity names and codes without CRS score labels", () => {
  assert.deepEqual(Array.from({ length: 8 }, (_, code) => toSyslogSeverity(code)), [0, 1, 2, 3, 4, 5, 6, 7]);
  assert.deepEqual(["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"].map(toSyslogSeverity), [0, 1, 2, 3, 4, 5, 6, 7]);
});

test("rates use observed request count", () => {
  assert.deepEqual(ratesFromBuckets(20, 2, 5), { recent_count: 20, error_rate_15m: 0.1, block_rate_15m: 0.25 });
});
