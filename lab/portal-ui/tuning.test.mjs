import test from "node:test";
import assert from "node:assert/strict";
import { normalizeTuning, renderTuning } from "./tuning.mjs";

const now = new Date("2026-10-07T00:00:00Z");
const valid = {
  id: "11111111-1111-4111-8111-111111111111",
  rule_id: 942100,
  site: "finance-vulnerable",
  path: "/api/lab/search",
  method: "GET",
  scope: "target",
  target: "ARGS:q",
  reason: "Narrow lab exception test",
  expires_at: "2026-10-08T00:00:00Z"
};

test("vulnerable tuning matches only the vulnerable Host", () => {
  const rendered = renderTuning(normalizeTuning([valid], now), now);
  assert.match(rendered, /REQUEST_HEADERS:Host "@streq localhost"/);
  assert.doesNotMatch(rendered, /patched\.localhost/);
  const lines = rendered.trim().split("\n");
  assert.doesNotMatch(lines[1], /ctl:ruleRemoveTargetById/);
  assert.match(lines[4], /TIME_EPOCH .*ctl:ruleRemoveTargetById=942100;ARGS:q/);
});

test("patched tuning matches only the patched Host", () => {
  const rendered = renderTuning(normalizeTuning([{ ...valid, site: "finance-patched" }], now), now);
  assert.match(rendered, /REQUEST_HEADERS:Host "@streq patched\.localhost"/);
  assert.doesNotMatch(rendered, /@streq localhost"/);
});

test("expired tuning is omitted", () => {
  const rendered = renderTuning(normalizeTuning([valid], now), new Date("2026-10-09T00:00:00Z"));
  assert.doesNotMatch(rendered, /SecRule REQUEST_FILENAME/);
});
