import { createHash } from "node:crypto";

const syslogSeverityByName = {
  emergency: 0, alert: 1, critical: 2, error: 3,
  warning: 4, notice: 5, informational: 6, info: 6, debug: 7
};

export function toSyslogSeverity(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (/^[0-7]$/.test(raw)) return Number(raw);
  return Object.hasOwn(syslogSeverityByName, raw) ? syslogSeverityByName[raw] : null;
}

export function extractCandidates(sources, blockingPL) {
  const groups = new Map();
  for (const source of sources) {
    const tx = source.transaction || source.audit_data?.transaction || {};
    const messages = tx.messages || source.messages || [];
    const request = tx.request || {};
    const headers = request.headers || {};
    const header = (name) => {
      const value = Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
      return Array.isArray(value) ? value[0] || "" : value || "";
    };
    const rawHost = header("host");
    const host = String(Array.isArray(rawHost) ? rawHost[0] || "" : rawHost).toLowerCase();
    const site = host.startsWith("patched.localhost") ? "finance-patched" : "finance-vulnerable";
    const method = String(request.method || source.http?.request?.method || "").toUpperCase();
    const path = String(request.uri || source.url?.path || "").split("?")[0];
    const requestId = String(header("x-request-id") || source.http?.request?.id || tx.id || tx.uniqueId || "");
    const stamp = String(source["@timestamp"] || "");
    if (!/^\/[A-Za-z0-9/_ .-]{1,119}$/.test(path)) continue;
    const serious = messages.filter((m) => {
      const detail = m.details || m.data || {};
      const id = Number(detail.ruleId || detail.rule_id || detail.id || m.ruleId);
      const sev = toSyslogSeverity(detail.severity ?? m.severity);
      return id >= 900000 && id < 949000 && Number.isFinite(sev) && sev <= 3;
    });
    for (const message of messages) {
      const details = message.details || message.data || {};
      const ruleId = Number(details.ruleId || details.rule_id || details.id || message.ruleId);
      if (!Number.isInteger(ruleId) || ruleId < 900000 || ruleId >= 949000) continue;
      const tags = details.tags || message.tags || [];
      const plTag = Array.isArray(tags) ? tags.find((tag) => /^paranoia-level\/[1-4]$/.test(tag)) : null;
      const pl = plTag ? Number(plTag.at(-1)) : 1;
      const match = [details.match, details.raw, details.data, message.match].filter((value) => typeof value === "string").join(" ");
      const targets = [...match.matchAll(/\b(ARGS_GET|ARGS_POST|ARGS|REQUEST_HEADERS|REQUEST_COOKIES):([A-Za-z0-9_.-]{1,64})\b/g)];
      const target = targets.find((candidate) => candidate[1].startsWith("ARGS")) || targets[0];
      const parameter = target?.[0] || "";
      const dimension = [site, ruleId, pl, method, path, parameter].join("|");
      const key = createHash("sha256").update(dimension).digest("hex");
      const severityRaw = String(details.severity ?? message.severity ?? "unknown").toLowerCase();
      const severitySyslog = toSyslogSeverity(severityRaw);
      const group = groups.get(key) || { key, site, rule_id: ruleId, pl, method, path, parameter, count: 0,
        days: 0, first_seen: stamp, last_seen: stamp, severity: severitySyslog === null ? severityRaw : String(severitySyslog),
        severity_syslog: severitySyslog, severity_source: severityRaw,
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
