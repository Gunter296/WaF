import test from "node:test";
import assert from "node:assert/strict";
import { normalizeTuning, renderTuning } from "./tuning.mjs";

const now = new Date("2026-09-29T00:00:00Z");
const valid = { id: "11111111-1111-4111-8111-111111111111", rule_id: 942100, path: "/api/lab/search", method: "GET", scope: "target", target: "ARGS:q", reason: "Confirmed lab false positive", expires_at: "2026-09-30T00:00:00Z" };

test("renders a scoped runtime exclusion before CRS", () => {
  const rules = normalizeTuning([valid], now);
  const lines = renderTuning(rules, now).trim().split("\n");
  assert.match(lines[1], /REQUEST_FILENAME "@streq \/api\/lab\/search"/);
  assert.doesNotMatch(lines[1], /ctl:ruleRemoveTargetById/);
  assert.match(lines[2], /REQUEST_METHOD "@streq GET"/);
  assert.match(lines[3], /REQUEST_HEADERS:Host/);
  assert.match(lines[4], /TIME_EPOCH "@lt .*ctl:ruleRemoveTargetById=942100;ARGS:q/);
});

test("rejects directive injection and broad scope", () => {
  for (const change of [{ path: '/ok"\nSecRuleEngine Off' }, { target: "ARGS:/.*" }, { rule_id: 100001 }, { path: "/", scope: "rule", target: "" }]) {
    const candidate = { ...valid, ...change };
    assert.throws(() => normalizeTuning([candidate], now));
  }
});

test("expired entries are excluded from generated rules", () => {
  const rules = normalizeTuning([valid], now);
  assert.doesNotMatch(renderTuning(rules, new Date("2026-10-01T00:00:00Z")), /SecRule REQUEST_FILENAME/);
});
