export function promotionDecision(policy, metrics, now = new Date()) {
  const a = policy.automation;
  if (a.mode !== "automatic") return { action: "none", reason: "manual mode" };
  const count = Number(metrics.request_count_7d);
  const firstSeen = new Date(metrics.first_seen);
  const dwellFrom = a.last_change_at ? new Date(a.last_change_at) : firstSeen;
  if (!Number.isFinite(count) || count < 10000 || !Number.isFinite(dwellFrom.getTime()) || now.getTime() - dwellFrom.getTime() < 7 * 86400000 || Number(metrics.recent_count) < 30) {
    return { action: "none", reason: "traffic or dwell gate not met" };
  }
  if (!a.flow_test_passed || metrics.open_severe === true) return { action: "none", reason: "flow test or false-positive review pending" };
  if (policy.mode === "On" && policy.blocking_pl >= a.target_pl) return { action: "none", reason: "target PL reached" };
  if (policy.mode === "On" && policy.detection_pl < policy.blocking_pl + 1) return { action: "none", reason: "raise Detection PL before promotion" };
  return policy.mode === "DetectionOnly"
    ? { action: "promote", mode: "On", blocking_pl: 1 }
    : { action: "promote", mode: "On", blocking_pl: Math.min(policy.blocking_pl + 1, a.target_pl) };
}

export function rollbackDecision(transition, metrics, now = new Date()) {
  const age = now.getTime() - new Date(transition.at).getTime();
  if (age >= 15 * 60000 && Number(metrics.recent_count) < 10) return { action: "rollback", reason: "insufficient post-change traffic" };
  const errorRate = Number(metrics.error_rate_15m);
  const blockRate = Number(metrics.block_rate_15m);
  if (!Number.isFinite(errorRate) || !Number.isFinite(blockRate)) return { action: "observe", reason: "metrics unavailable" };
  const baseline = transition.baseline || {};
  if (errorRate > Math.max(0.05, Number(baseline.error_rate || 0) * 2) || blockRate > Math.max(0.10, Number(baseline.block_rate || 0) * 2)) {
    return { action: "rollback", reason: "error or block rate spike" };
  }
  return age < 15 * 60000 ? { action: "observe", reason: "rollback window" } : { action: "complete" };
}
