import { extractCandidates, ratesFromBuckets } from "./learning.mjs";

const es = process.env.ELASTICSEARCH_URL || "http://elasticsearch:9200";
const portal = process.env.PORTAL_URL || "http://portal:8090";
const token = process.env.LAB_AUTOMATION_TOKEN || "local-learning-worker-token";
const period = Math.max(15, Number(process.env.POLL_SECONDS) || 60) * 1000;

async function jsonRequest(url, body, headers = {}) {
  const response = await fetch(url, { method: body === undefined ? "GET" : "POST", headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`${url}: ${response.status} ${(await response.text()).slice(0, 200)}`);
  return response.json();
}

async function esSearch(query) { return jsonRequest(`${es}/waf-lab-*/_search?ignore_unavailable=true&allow_no_indices=true`, query); }

async function tick() {
  const policy = (await jsonRequest(`${portal}/api/policy`)).document;
  const audit = await esSearch({ size: 5000, track_total_hits: true, sort: [{ "@timestamp": { order: "desc" } }],
    query: { bool: { filter: [{ range: { "@timestamp": { gte: "now-4d" } } }, { exists: { field: "messages.details.ruleId" } }] } } });
  const hits = audit.hits?.hits || [];
  const candidates = extractCandidates(hits.map((hit) => hit._source), Number(policy.blocking_pl || 1));
  const truncated = Number(audit.hits?.total?.value || 0) > hits.length || candidates.length > 100;
  if (candidates.length) await jsonRequest(`${portal}/api/learning`, candidates.slice(0, 100), { "x-lab-automation-token": token });

  const accessFilter = { term: { "event.dataset": "haproxy.access" } };
  const routeFilter = { term: { "lab.route": "waf" } };
  const siteFilter = { term: { "lab.backend": "finance_waf_with_fallback" } };
  const sevenDays = await esSearch({ size: 0, track_total_hits: true,
    query: { bool: { filter: [accessFilter, routeFilter, siteFilter, { range: { "@timestamp": { gte: "now-7d" } } }] } } });
  const first = await esSearch({ size: 0, query: { bool: { filter: [accessFilter, routeFilter, siteFilter] } }, aggs: { first_seen: { min: { field: "@timestamp" } } } });
  const recentFrom = policy.automation?.transition?.at || "now-15m";
  const recent = await esSearch({ size: 0, track_total_hits: true, query: { bool: { filter: [accessFilter, routeFilter, siteFilter, { range: { "@timestamp": { gte: recentFrom } } }] } },
    aggs: { errors: { filter: { range: { "http.response.status_code": { gte: 500 } } } },
      blocks: { filter: { terms: { "http.response.status_code": [403, 429] } } } } });
  const total = Number(recent.hits?.total?.value || 0);
  const rates = ratesFromBuckets(total, Number(recent.aggregations?.errors?.doc_count || 0), Number(recent.aggregations?.blocks?.doc_count || 0));
  const blockers = await jsonRequest(`${portal}/api/learning/blockers`);
  const result = await jsonRequest(`${portal}/api/automation/evaluate`, {
    request_count_7d: Number(sevenDays.hits?.total?.value || 0), first_seen: first.aggregations?.first_seen?.value_as_string,
    open_severe: blockers.open_severe || truncated, ...rates
  }, { "x-lab-automation-token": token });
  console.log(JSON.stringify({ time: new Date().toISOString(), candidates: candidates.length, truncated, metrics: rates, result }));
}

for (;;) {
  try { await tick(); }
  catch (error) { console.error(JSON.stringify({ time: new Date().toISOString(), error: error.message })); }
  await new Promise((resolve) => setTimeout(resolve, period));
}
