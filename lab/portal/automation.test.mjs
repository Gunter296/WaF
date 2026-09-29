import test from "node:test";
import assert from "node:assert/strict";
import { promotionDecision, rollbackDecision } from "./automation.mjs";

const now = new Date("2026-09-29T00:00:00Z");
const policy = { mode: "On", blocking_pl: 1, detection_pl: 2,
  automation: { mode: "automatic", target_pl: 2, flow_test_passed: true, last_change_at: "2026-09-21T00:00:00Z" } };
const metrics = { request_count_7d: 10000, first_seen: "2026-09-01T00:00:00Z", recent_count: 40, open_severe: false };

test("promotes one PL only when all gates pass", () => {
  assert.deepEqual(promotionDecision(policy, metrics, now), { action: "promote", mode: "On", blocking_pl: 2 });
  assert.equal(promotionDecision(policy, { ...metrics, request_count_7d: 9999 }, now).action, "none");
  assert.equal(promotionDecision({ ...policy, detection_pl: 1 }, metrics, now).action, "none");
  assert.equal(promotionDecision(policy, { ...metrics, open_severe: true }, now).action, "none");
});

test("rollback reacts to spikes and missing post-change evidence", () => {
  const transition = { at: "2026-09-28T23:50:00Z", baseline: { error_rate: 0.01, block_rate: 0.02 } };
  assert.equal(rollbackDecision(transition, { recent_count: 30, error_rate_15m: 0.1, block_rate_15m: 0.02 }, now).action, "rollback");
  assert.equal(rollbackDecision(transition, { recent_count: 30, error_rate_15m: 0.01, block_rate_15m: 0.02 }, now).action, "observe");
  assert.equal(rollbackDecision(transition, { recent_count: 5, error_rate_15m: 0, block_rate_15m: 0 }, new Date("2026-09-29T00:06:00Z")).action, "rollback");
});
