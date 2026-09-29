import test from "node:test";
import assert from "node:assert/strict";
import { extractCandidates, ratesFromBuckets } from "./learning.mjs";

test("groups Coraza events by rule, PL, method, path and parameter", () => {
  const source = { "@timestamp": "2026-09-29T01:00:00Z", transaction: { id: "request-1", request: { method: "GET", uri: "/api/lab/search?q=test" },
    messages: [{ details: { ruleId: 942100, tags: ["paranoia-level/2"], match: "Matched ARGS:q", severity: "Warning" } }] } };
  const [group] = extractCandidates([source, { ...source, "@timestamp": "2026-09-28T01:00:00Z", transaction: { ...source.transaction, id: "request-2" } }], 1);
  assert.equal(group.count, 2);
  assert.equal(group.days, 2);
  assert.equal(group.estimated_blocks, 2);
  assert.equal(group.parameter, "ARGS:q");
  assert.equal(group.site, "finance-vulnerable");
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
  assert.equal(group.severity, "high");
});

test("rates use observed request count", () => {
  assert.deepEqual(ratesFromBuckets(20, 2, 5), { recent_count: 20, error_rate_15m: 0.1, block_rate_15m: 0.25 });
});
