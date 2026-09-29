import { createHash } from "node:crypto";

export function extractCandidates(sources, blockingPL) {
  const groups = new Map();
  for (const source of sources) {
    const tx = source.transaction || source.audit_data?.transaction || {};
    const messages = tx.messages || source.messages || [];
    const request = tx.request || {};
    const rawHost = request.headers?.host || request.headers?.Host || [];
    const host = String(Array.isArray(rawHost) ? rawHost[0] || "" : rawHost).toLowerCase();
    const site = host.startsWith("patched.localhost") ? "finance-patched" : "finance-vulnerable";
    const method = String(request.method || source.http?.request?.method || "").toUpperCase();
    const path = String(request.uri || source.url?.path || "").split("?")[0];
    const requestId = String(tx.id || tx.uniqueId || source.http?.request?.id || "");
    const stamp = String(source["@timestamp"] || "");
    if (!/^\/[A-Za-z0-9/_ .-]{1,119}$/.test(path)) continue;
    const serious = messages.filter((m) => {
      const detail = m.details || m.data || {};
      const id = Number(detail.ruleId || detail.rule_id || m.ruleId);
      const sev = Number(detail.severity || m.severity);
      return id >= 900000 && id < 949000 && Number.isFinite(sev) && sev <= 3;
    });
    for (const message of messages) {
      const details = message.details || message.data || {};
      const ruleId = Number(details.ruleId || details.rule_id || message.ruleId);
      if (!Number.isInteger(ruleId) || ruleId < 900000 || ruleId > 999999) continue;
      const tags = details.tags || message.tags || [];
      const plTag = Array.isArray(tags) ? tags.find((tag) => /^paranoia-level\/[1-4]$/.test(tag)) : null;
      const pl = plTag ? Number(plTag.at(-1)) : 1;
      const match = String(details.match || message.match || "");
      const parameter = /\b(ARGS|ARGS_GET|ARGS_POST|REQUEST_HEADERS|REQUEST_COOKIES):([A-Za-z0-9_.-]{1,64})\b/.exec(match)?.[0] || "";
      const dimension = [site, ruleId, pl, method, path, parameter].join("|");
      const key = createHash("sha256").update(dimension).digest("hex");
      const severityRaw = String(details.severity || message.severity || "unknown").toLowerCase();
      const severity = severityRaw === "0" || severityRaw === "1" ? "critical" : severityRaw === "2" || severityRaw === "3" ? "high" : severityRaw;
      const group = groups.get(key) || { key, site, rule_id: ruleId, pl, method, path, parameter, count: 0,
        days: 0, first_seen: stamp, last_seen: stamp, severity,
        other_serious: false, estimated_blocks: 0, sample_request_ids: [], _days: new Set(), _requests: new Set() };
      const eventKey = requestId || `${stamp}|${dimension}`;
      if (group._requests.has(eventKey)) continue;
      group._requests.add(eventKey);
      group.count++;
      if (serious.some((m) => m !== message)) group.other_serious = true;
      if (pl > blockingPL) group.estimated_blocks++;
      if (stamp < group.first_seen) group.first_seen = stamp;
      if (stamp > group.last_seen) group.last_seen = stamp;
      if (stamp) group._days.add(stamp.slice(0, 10));
      if (requestId && group.sample_request_ids.length < 5 && !group.sample_request_ids.includes(requestId)) group.sample_request_ids.push(requestId);
      groups.set(key, group);
    }
  }
  return [...groups.values()].map(({ _days, _requests, ...group }) => ({ ...group, days: _days.size }));
}

export function ratesFromBuckets(total, errors, blocks) {
  return { recent_count: total, error_rate_15m: total ? errors / total : 0, block_rate_15m: total ? blocks / total : 0 };
}
