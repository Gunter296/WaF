import http from "node:http";
import { readFile, writeFile, rename, appendFile } from "node:fs/promises";
import { Pool } from "pg";
import { randomUUID } from "node:crypto";
import { normalizeTuning, renderTuning } from "./tuning.mjs";
import { normalizeIPPolicy, renderIPPolicy } from "./ip-policy.mjs";
import { promotionDecision, rollbackDecision } from "./automation.mjs";
import { fetchLogPage } from "./logs.mjs";

const port = Number(process.env.PORT || 8090);
const policyFile = process.env.POLICY_FILE || "/shared/policy.json";
const logFile = process.env.LAB_LOG_FILE || "/var/log/lab/portal.jsonl";
const tuningFile = process.env.TUNING_FILE || "/tuning/tuning.conf";
const ipPolicyFile = process.env.IP_POLICY_FILE || "/tuning/ip-policy.conf";
const caddyFile = process.env.CADDYFILE || "/waf/Caddyfile";
const caddyAdmin = process.env.CADDY_ADMIN_URL || "http://172.31.0.3:2019";
const elasticsearchUrl = process.env.ELASTICSEARCH_URL || "http://elasticsearch:9200";
const automationToken = process.env.LAB_AUTOMATION_TOKEN || "local-learning-worker-token";
const pool = new Pool({ host: process.env.PGHOST, port: Number(process.env.PGPORT || 5432), database: process.env.PGDATABASE, user: process.env.PGUSER, password: process.env.PGPASSWORD });

const defaults = {
  version: 0, enabled: true, mode: "On", blocking_pl: 1, detection_pl: 2,
  cve_rules: { "CVE-2026-64642": false, "CVE-2026-64645": false },
  crs_exclusions: { sqli_search: false },
  tuning_rules: [],
  automation: { mode: "manual", target_pl: 2, flow_test_passed: false, auto_exceptions: false, approved_paths: [], last_change_at: null, transition: null },
  rate_limit: { enabled: true, requests: 30, window_seconds: 10, range_requests: 120, range_window_seconds: 10, prefix_v4: 32, prefix_v6: 128, range_prefix_v4: 24, range_prefix_v6: 64 },
  geo: { enabled: false, deny: [], allow: [], fixtures: { "172.30.0.10": "VN", "172.30.0.20": "US" } },
  ip_policy: { enabled: false, deny: [], allow: [] },
  bot_detection: { enabled: true, unique_paths: 8, window_seconds: 30, spam_requests: 10, spam_window_seconds: 10, action: "observe" },
  behavior: {
    login_failures: { enabled: true, limit: 5, window_seconds: 60, action: "block" },
    not_found_burst: { enabled: true, limit: 15, window_seconds: 30, action: "observe" },
    sequential_documents: { enabled: true, limit: 4, window_seconds: 30, action: "observe" }
  }
};

async function log(action, details = {}) {
  const event = { "@timestamp": new Date().toISOString(), event: { dataset: "portal.audit", action }, ...details };
  await appendFile(logFile, `${JSON.stringify(event)}\n`).catch(() => {});
}

async function recentLogs(params) {
  return fetchLogPage(params, elasticsearchUrl);
}

async function ensureStorage() {
  await pool.query("CREATE TABLE IF NOT EXISTS lab_policy (id integer PRIMARY KEY CHECK (id = 1), document jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE TABLE IF NOT EXISTS lab_audit (id bigserial PRIMARY KEY, action text NOT NULL, document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("CREATE TABLE IF NOT EXISTS lab_learning (key text PRIMARY KEY, document jsonb NOT NULL, status text NOT NULL DEFAULT 'candidate', updated_at timestamptz NOT NULL DEFAULT now())");
  await pool.query("ALTER TABLE lab_learning ADD COLUMN IF NOT EXISTS review_note text NOT NULL DEFAULT ''");
  await pool.query("CREATE TABLE IF NOT EXISTS lab_automation_health (id integer PRIMARY KEY CHECK (id=1), last_seen timestamptz NOT NULL)");
  const { rows } = await pool.query("SELECT document FROM lab_policy WHERE id=1");
  const existing = rows[0]?.document || {};
  let policy = { ...structuredClone(defaults), ...existing, bot_detection: { ...defaults.bot_detection, ...(existing.bot_detection || {}) }, automation: { ...defaults.automation, ...(existing.automation || {}) }, tuning_rules: existing.tuning_rules || [] };
  await saveFile(policy);
  await writeTuning(renderTuning(normalizeTuning(policy.tuning_rules || [], new Date(), new Set((policy.tuning_rules || []).map((r) => r.id)))));
  await writeIPPolicy(renderIPPolicy(normalizeIPPolicy(policy.ip_policy || defaults.ip_policy), policy.enabled !== false));
  if (!rows.length) await pool.query("INSERT INTO lab_policy(id,document) VALUES(1,$1)", [policy]);
  else await pool.query("UPDATE lab_policy SET document=$1 WHERE id=1", [policy]);
}

async function writeTuning(content) {
  const temp = `${tuningFile}.tmp`;
  await writeFile(temp, content, { mode: 0o640 });
  await rename(temp, tuningFile);
}

async function writeIPPolicy(content) {
  const temp = `${ipPolicyFile}.tmp`;
  await writeFile(temp, content, { mode: 0o640 });
  await rename(temp, ipPolicyFile);
}

async function reloadCaddy() {
  let config = await readFile(caddyFile, "utf8");
  for (const [include, file] of [
    ["Include /etc/coraza-tuning/ip-policy.conf", ipPolicyFile],
    ["Include /etc/coraza-tuning/tuning.conf", tuningFile]
  ]) {
    if (!config.includes(include)) throw new Error(`Caddyfile is missing expected Coraza include: ${include}`);
    const directives = (await readFile(file, "utf8")).trimEnd();
    config = config.replace(include, directives);
  }
  const response = await fetch(`${caddyAdmin}/load`, {
    method: "POST",
    headers: { "content-type": "text/caddyfile", "cache-control": "must-revalidate", origin: new URL(caddyAdmin).origin },
    body: config,
    signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error(`Caddy reload failed (${response.status}): ${(await response.text()).slice(0, 500)}`);
}

function normalizeAutomation(input, previous = defaults.automation) {
  const mode = input?.mode === "automatic" ? "automatic" : "manual";
  const target = Number(input?.target_pl);
  if (!Number.isInteger(target) || target < 1 || target > 4) throw new Error("target PL must be 1–4");
  const paths = Array.isArray(input?.approved_paths) ? input.approved_paths.map(String).map((v) => v.trim()) : [];
  if (paths.length > 20 || paths.some((v) => !/^\/[A-Za-z0-9/_ .-]{1,119}$/.test(v) || v.includes("..") || v.includes("//"))) throw new Error("invalid approved paths");
  return { mode, target_pl: target, flow_test_passed: input?.flow_test_passed === true, auto_exceptions: input?.auto_exceptions === true,
    approved_paths: paths, last_change_at: previous.last_change_at || null, transition: previous.transition || null };
}

async function saveFile(policy) {
  const temp = `${policyFile}.tmp`;
  await writeFile(temp, `${JSON.stringify(policy, null, 2)}\n`, { mode: 0o640 });
  await rename(temp, policyFile);
}

async function currentPolicy() {
  const { rows } = await pool.query("SELECT document,updated_at FROM lab_policy WHERE id=1");
  return rows[0] ?? { document: defaults, updated_at: new Date().toISOString() };
}

async function savePolicy(incoming, internalAutomation = null) {
  if (!incoming || !["On", "DetectionOnly"].includes(incoming.mode)) throw new Error("mode must be On or DetectionOnly");
  const next = structuredClone(defaults);
  next.enabled = incoming.enabled !== false;
  next.mode = incoming.mode;
  next.blocking_pl = Math.max(1, Math.min(4, Number(incoming.blocking_pl) || 1));
  next.detection_pl = Math.max(1, Math.min(4, Number(incoming.detection_pl) || 2));
  next.cve_rules = { ...next.cve_rules, ...incoming.cve_rules };
  next.crs_exclusions = { sqli_search: Boolean(incoming.crs_exclusions?.sqli_search) };
  const previous = (await currentPolicy()).document;
  if (!Number.isInteger(incoming.version) || incoming.version !== previous.version) throw new Error("policy changed; reload portal before saving");
  next.version = previous.version + 1;
  next.tuning_rules = normalizeTuning(incoming.tuning_rules || [], new Date(), new Set((previous.tuning_rules || []).map((r) => r.id)));
  next.automation = normalizeAutomation(incoming.automation || defaults.automation, previous.automation || defaults.automation);
  if (internalAutomation) next.automation = { ...next.automation, ...internalAutomation };
  else if (next.mode !== previous.mode || next.blocking_pl !== previous.blocking_pl || next.detection_pl !== previous.detection_pl) {
    next.automation.last_change_at = new Date().toISOString();
    next.automation.transition = null;
    next.automation.flow_test_passed = false;
  }
  else if (next.automation.mode === "manual" && previous.automation?.mode === "automatic") {
    next.automation.transition = null;
  }
  next.rate_limit = { ...next.rate_limit, ...incoming.rate_limit };
  next.geo = { ...next.geo, ...incoming.geo };
  next.behavior = { ...next.behavior, ...incoming.behavior };
  next.bot_detection = { ...next.bot_detection, ...incoming.bot_detection };
  next.bot_detection.enabled = Boolean(next.bot_detection.enabled);
  if (!Number.isInteger(next.bot_detection.unique_paths) || next.bot_detection.unique_paths < 3 || next.bot_detection.unique_paths > 100) throw new Error("bot unique_paths must be 3–100");
  if (!Number.isInteger(next.bot_detection.window_seconds) || next.bot_detection.window_seconds < 1 || next.bot_detection.window_seconds > 3600) throw new Error("bot window_seconds must be 1–3600");
  if (!Number.isInteger(next.bot_detection.spam_requests) || next.bot_detection.spam_requests < 1 || next.bot_detection.spam_requests > 10000) throw new Error("bot spam_requests must be 1–10000");
  if (!Number.isInteger(next.bot_detection.spam_window_seconds) || next.bot_detection.spam_window_seconds < 1 || next.bot_detection.spam_window_seconds > 3600) throw new Error("bot spam_window_seconds must be 1–3600");
  if (!["observe", "block"].includes(next.bot_detection.action)) throw new Error("invalid bot action");
  for (const value of [next.rate_limit.requests, next.rate_limit.range_requests, next.rate_limit.window_seconds, next.rate_limit.range_window_seconds]) {
    if (!Number.isInteger(value) || value < 1 || value > 100000) throw new Error("rate values must be integers from 1 to 100000");
  }
  if (![32, 24, 16, 8].includes(Number(next.rate_limit.prefix_v4)) || ![128, 64, 48].includes(Number(next.rate_limit.prefix_v6))) throw new Error("unsupported per-IP prefix");
  if (![24, 16, 8].includes(Number(next.rate_limit.range_prefix_v4)) || ![64, 48].includes(Number(next.rate_limit.range_prefix_v6))) throw new Error("unsupported range prefix");
  next.rate_limit.enabled = Boolean(next.rate_limit.enabled);
  next.geo.enabled = Boolean(next.geo.enabled);
  next.geo.deny = Array.isArray(next.geo.deny) ? next.geo.deny.map(String).map((v) => v.trim().toUpperCase()).filter(Boolean) : [];
  next.geo.allow = Array.isArray(next.geo.allow) ? next.geo.allow.map(String).map((v) => v.trim().toUpperCase()).filter(Boolean) : [];
  next.geo.fixtures = typeof next.geo.fixtures === "object" && next.geo.fixtures ? next.geo.fixtures : defaults.geo.fixtures;
  next.ip_policy = normalizeIPPolicy(incoming.ip_policy || defaults.ip_policy);
  for (const group of Object.values(next.behavior)) {
    group.enabled = Boolean(group.enabled);
    group.limit = Math.max(1, Math.min(10000, Number(group.limit) || 1));
    group.window_seconds = Math.max(1, Math.min(3600, Number(group.window_seconds) || 10));
    if (!["observe", "block"].includes(group.action)) group.action = "observe";
  }
  const oldTuning = await readFile(tuningFile, "utf8").catch(() => "# Empty tuning\n");
  const newTuning = renderTuning(next.tuning_rules);
  const oldIPPolicy = await readFile(ipPolicyFile, "utf8").catch(() => "# Empty IP policy\n");
  const newIPPolicy = renderIPPolicy(next.ip_policy, next.enabled);
  const tuningChanged = oldTuning !== newTuning || oldIPPolicy !== newIPPolicy;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO lab_policy(id,document) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET document=EXCLUDED.document,updated_at=now()", [next]);
    await client.query("INSERT INTO lab_audit(action,document) VALUES($1,$2)", ["policy_updated", next]);
    if (tuningChanged) {
      await writeTuning(newTuning);
      await writeIPPolicy(newIPPolicy);
      await reloadCaddy();
    }
    await saveFile(next);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    await saveFile(previous).catch(() => {});
    if (tuningChanged) {
      await writeTuning(oldTuning).catch(() => {});
      await writeIPPolicy(oldIPPolicy).catch(() => {});
      await reloadCaddy().catch(() => {});
    }
    throw error;
  }
  finally { client.release(); }
  await log("policy_updated", { lab: { mode: next.mode } });
  return next;
}

let writeQueue = Promise.resolve();
function serialize(action) {
  const result = writeQueue.then(action);
  writeQueue = result.catch(() => {});
  return result;
}

async function readJson(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 200_000) throw new Error("request too large");
  }
  return JSON.parse(body);
}

function sendJson(res, status, value) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" }).end(JSON.stringify(value));
}

function requireWorker(req) {
  if (req.headers["x-lab-automation-token"] !== automationToken) throw new Error("worker token required");
}

function requireLocalMutation(req) {
  if (!String(req.headers["content-type"] || "").startsWith("application/json")) throw new Error("application/json required");
  if (req.headers.origin && req.headers.origin !== "http://127.0.0.1:8090" && req.headers.origin !== "http://localhost:8090") throw new Error("cross-origin portal update denied");
  if (req.headers["sec-fetch-site"] === "cross-site") throw new Error("cross-site portal update denied");
}

async function learningRows() {
  const { rows } = await pool.query("SELECT key, document, status, review_note, updated_at FROM lab_learning ORDER BY updated_at DESC LIMIT 200");
  return rows;
}

async function hasOpenSevere(policy) {
  const { rows } = await pool.query("SELECT document FROM lab_learning WHERE status IN ('needs_review','confirmed_fp') AND (document->>'severity_syslog' IN ('0','1','2','3') OR document->>'severity' IN ('high','critical'))");
  return rows.some(({ document: item }) => !(policy.tuning_rules || []).some((rule) =>
    rule.enabled !== false && new Date(rule.expires_at) > new Date() && rule.rule_id === item.rule_id && rule.site === item.site && rule.path === item.path && rule.method === item.method &&
    (rule.scope === "rule" || rule.target === item.parameter)));
}

async function upsertLearning(items) {
  if (!Array.isArray(items) || items.length > 100) throw new Error("invalid learning batch");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const item of items) {
      const key = String(item.key || "");
      if (!/^[A-Za-z0-9|:_./-]{1,220}$/.test(key)) throw new Error("invalid learning key");
      const document = {
        site: String(item.site || "finance-vulnerable"), rule_id: Number(item.rule_id), pl: Number(item.pl), method: String(item.method || ""), path: String(item.path || ""),
        parameter: String(item.parameter || ""), count: Number(item.count || 0), days: Number(item.days || 0),
        first_seen: item.first_seen, last_seen: item.last_seen, severity: String(item.severity ?? "unknown"),
        severity_syslog: Number.isInteger(item.severity_syslog) && item.severity_syslog >= 0 && item.severity_syslog <= 7 ? item.severity_syslog : null,
        severity_source: String(item.severity_source ?? item.severity ?? "unknown"),
        other_serious: item.other_serious === true, estimated_blocks: Number(item.estimated_blocks || 0),
        sample_request_ids: Array.isArray(item.sample_request_ids) ? item.sample_request_ids.slice(0, 5).map(String) : []
      };
      await client.query("INSERT INTO lab_learning(key,document) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET document=EXCLUDED.document,updated_at=now()", [key, document]);
    }
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
  await log("learning_updated", { lab: { candidates: items.length } });
}

async function evaluateAutomation(metrics) {
  await pool.query("INSERT INTO lab_automation_health(id,last_seen) VALUES(1,now()) ON CONFLICT(id) DO UPDATE SET last_seen=now()");
  let policy = (await currentPolicy()).document;
  const now = new Date();
  const active = (policy.tuning_rules || []).filter((r) => new Date(r.expires_at) > now);
  if (active.length !== (policy.tuning_rules || []).length) {
    policy.tuning_rules = active;
    policy = await savePolicy(policy);
    await log("tuning_expired");
  }
  const a = policy.automation || defaults.automation;
  if (a.mode !== "automatic") return { action: "none", reason: "manual mode" };
  if (a.transition) {
    const decision = rollbackDecision(a.transition, metrics, now);
    if (decision.action === "rollback") {
      policy.mode = a.transition.previous_mode;
      policy.blocking_pl = a.transition.previous_pl;
      await savePolicy(policy, { transition: null, last_change_at: now.toISOString() });
      await log("automatic_pl_rollback", { lab: { reason: decision.reason } });
      return decision;
    }
    if (decision.action === "observe") return decision;
    policy = await savePolicy(policy, { transition: null });
  }

  if (a.auto_exceptions) {
    const { rows } = await pool.query("SELECT key,document,review_note FROM lab_learning WHERE status='confirmed_fp' ORDER BY updated_at DESC LIMIT 100");
    for (const row of rows) {
      const item = row.document;
      const pathApproved = a.approved_paths?.includes(item.path);
      const target = item.parameter;
      const span = new Date(item.last_seen).getTime() - new Date(item.first_seen).getTime();
      if (item.site !== "finance-vulnerable" || !pathApproved || item.count < 30 || item.days < 3 || span < 48 * 3600000 || item.other_serious === true || !/^(ARGS|ARGS_GET|ARGS_POST|REQUEST_HEADERS|REQUEST_COOKIES):[A-Za-z0-9_.-]{1,64}$/.test(target)) continue;
      if ((policy.tuning_rules || []).some((r) => r.rule_id === item.rule_id && r.site === item.site && r.path === item.path && r.method === item.method && r.target === target)) continue;
      const candidate = { id: randomUUID(), rule_id: item.rule_id, site: item.site, path: item.path, method: item.method, scope: "target", target,
        reason: `Confirmed FP: ${row.review_note || row.key}`.slice(0, 200), expires_at: new Date(now.getTime() + 86400000).toISOString(), source: "automatic" };
      policy.tuning_rules = [...(policy.tuning_rules || []), candidate];
      await savePolicy(policy);
      await pool.query("UPDATE lab_learning SET status='auto_applied',updated_at=now() WHERE key=$1", [row.key]);
      await log("automatic_tuning_applied", { rule: { id: String(item.rule_id) }, lab: { path: item.path } });
      return { action: "auto_exception", rule_id: item.rule_id, path: item.path };
    }
  }

  const decision = promotionDecision(policy, metrics, now);
  if (decision.action !== "promote") return decision;
  const previousMode = policy.mode;
  const previousPL = policy.blocking_pl;
  policy.mode = decision.mode;
  policy.blocking_pl = decision.blocking_pl;
  const baseline = { error_rate: Number(metrics.error_rate_15m || 0), block_rate: Number(metrics.block_rate_15m || 0) };
  await savePolicy(policy, { last_change_at: now.toISOString(), transition: { at: now.toISOString(), previous_mode: previousMode, previous_pl: previousPL, baseline } });
  await log("automatic_pl_promoted", { lab: { from: previousPL, to: policy.blocking_pl, mode: policy.mode } });
  return { action: "promote", mode: policy.mode, blocking_pl: policy.blocking_pl };
}

const assets = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/advanced", ["index.html", "text/html; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/demo.js", ["demo.js", "text/javascript; charset=utf-8"]]
]);
const server = http.createServer(async (req, res) => {
  try {
    if (req.url === "/healthz") { res.writeHead(200).end("ok"); return; }
    if (req.url === "/api/policy" && req.method === "GET") { sendJson(res, 200, await currentPolicy()); return; }
    if (req.url === "/api/policy" && req.method === "PUT") {
      requireLocalMutation(req);
      const incoming = await readJson(req);
      const saved = await serialize(() => savePolicy(incoming)); sendJson(res, 200, saved); return;
    }
    if (req.url === "/api/learning" && req.method === "GET") { sendJson(res, 200, await learningRows()); return; }
    if (new URL(req.url, "http://localhost").pathname === "/api/logs" && req.method === "GET") {
      sendJson(res, 200, await recentLogs(new URL(req.url, "http://localhost").searchParams)); return;
    }
    if (req.url === "/api/learning/blockers" && req.method === "GET") {
      sendJson(res, 200, { open_severe: await hasOpenSevere((await currentPolicy()).document) }); return;
    }
    if (req.url === "/api/automation/status" && req.method === "GET") {
      const { rows } = await pool.query("SELECT last_seen FROM lab_automation_health WHERE id=1");
      sendJson(res, 200, { worker_last_seen: rows[0]?.last_seen || null, automation: (await currentPolicy()).document.automation }); return;
    }
    if (req.url === "/api/learning" && req.method === "POST") {
      requireWorker(req); await upsertLearning(await readJson(req)); sendJson(res, 200, { ok: true }); return;
    }
    if (req.url === "/api/automation/evaluate" && req.method === "POST") {
      requireWorker(req); const metrics = await readJson(req);
      sendJson(res, 200, await serialize(() => evaluateAutomation(metrics))); return;
    }
    const labelMatch = /^\/api\/learning\/([A-Za-z0-9|:_./-]{1,220})\/label$/.exec(req.url || "");
    if (labelMatch && req.method === "POST") {
      requireLocalMutation(req);
      const { status, evidence } = await readJson(req);
      if (!["candidate", "confirmed_fp", "needs_review", "dismissed"].includes(status)) throw new Error("invalid learning label");
      const note = String(evidence || "").trim();
      if (status === "confirmed_fp" && (note.length < 12 || note.length > 500)) throw new Error("confirmed false positive requires 12–500 characters of evidence");
      const result = await pool.query("UPDATE lab_learning SET status=$1,review_note=$2,updated_at=now() WHERE key=$3", [status, note, labelMatch[1]]);
      if (!result.rowCount) { sendJson(res, 404, { error: "unknown candidate" }); return; }
      await log("learning_labeled", { lab: { key: labelMatch[1], status } });
      sendJson(res, 200, { ok: true }); return;
    }


    const asset = assets.get(new URL(req.url, "http://localhost").pathname);
    if (asset && req.method === "GET") {
      const content = await readFile(new URL("./public/" + asset[0], import.meta.url));
      res.writeHead(200, { "content-type": asset[1], "cache-control": "no-store", "x-content-type-options": "nosniff" }).end(content);
      return;
    }
    res.writeHead(404).end("not found");
  } catch (error) { res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: error.message })); }
});

await ensureStorage();
setInterval(() => serialize(async () => {
  let policy = (await currentPolicy()).document;
  if ((policy.tuning_rules || []).some((r) => new Date(r.expires_at) <= new Date())) {
    policy.tuning_rules = policy.tuning_rules.filter((r) => new Date(r.expires_at) > new Date());
    policy = await savePolicy(policy);
    await log("tuning_expired");
  }
  const transition = policy.automation?.transition;
  if (transition) {
    const { rows } = await pool.query("SELECT last_seen FROM lab_automation_health WHERE id=1");
    const lastSeen = rows[0] ? new Date(rows[0].last_seen).getTime() : 0;
    if (Date.now() - lastSeen > 120000) {
      policy.mode = transition.previous_mode;
      policy.blocking_pl = transition.previous_pl;
      await savePolicy(policy, { transition: null, last_change_at: new Date().toISOString() });
      await log("automatic_pl_rollback", { lab: { reason: "learning_worker_unavailable" } });
    }
  }
}).catch((error) => console.error("policy maintenance:", error.message)), 60000).unref();
server.listen(port, "0.0.0.0", () => console.log(`portal listening on ${port}`));

void (async () => {
  for (let attempt = 0; attempt < 30; attempt++) {
    try { await serialize(() => reloadCaddy()); await log("waf_config_reconciled"); return; }
    catch (error) {
      if (attempt === 29) console.error("WAF startup reload failed:", error.message);
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
})();
