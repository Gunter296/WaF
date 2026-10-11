import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const edge = (process.env.FINANCE_EDGE_URL || "http://127.0.0.1:8080").replace(/\/$/, "");
const host = process.env.FINANCE_EDGE_HOST || "localhost";
const email = process.env.FINANCE_DEMO_EMAIL || "an.demo@northstar.test";
const password = process.env.FINANCE_DEMO_PASSWORD || "demo1234";
const elasticsearch = (process.env.ELASTICSEARCH_URL || "http://127.0.0.1:9200").replace(/\/$/, "");
const stage = process.argv[2] || "before";
if (!["before", "after", "revoked"].includes(stage)) throw new Error("Use stage: before, after, or revoked");

const results = [];
async function send(label, path, options = {}, cookie = "") {
  const response = await fetch(`${edge}${path}`, {
    ...options,
    headers: { host, ...(cookie ? { cookie } : {}), ...(options.headers || {}) },
    redirect: "manual",
  });
  const body = await response.json().catch(() => null);
  const id = response.headers.get("x-request-id");
  results.push({ label, status: response.status, request_id: id, host, path });
  return { response, body, id };
}

const login = await send("login", "/api/auth/login", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password }),
});
if (login.response.status !== 200) throw new Error(`Demo login failed with HTTP ${login.response.status}; check lab seed account setup.`);
const cookie = (login.response.headers.get("set-cookie") || "").split(";")[0];
if (!cookie.startsWith("lab_session=")) throw new Error("Server session cookie was not issued.");

const account = await send("account_summary", "/api/accounts/me", {}, cookie);
const ordinary = await send("ordinary_transactions", "/api/transactions?page=1&limit=5", {}, cookie);
if (account.response.status !== 200 || ordinary.response.status !== 200) throw new Error("Normal authenticated traffic did not complete.");
const example = await send("reconcile_example", "/api/transactions/reconcile/example", {}, cookie);
if (example.response.status !== 200) throw new Error(`Could not load the seeded reconciliation example (HTTP ${example.response.status}).`);
const expressions = process.env.FINANCE_RECONCILE_EXPRESSION ? [process.env.FINANCE_RECONCILE_EXPRESSION] : [
  example.body.expression,
  example.body.expression.replace("'O''Connor Market'", '"O\'Connor Market"'),
];
let expression = expressions[0];
let reconcile;
let confirmedFalsePositive = false;
for (const [index, candidate] of expressions.entries()) {
  expression = candidate;
  reconcile = await send(`valid_reconciliation_candidate_${index + 1}`, "/api/transactions/reconcile/search", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ expression: candidate }),
  }, cookie);
  if (stage === "after" && reconcile.response.status === 200) break;
  if (stage !== "after" && reconcile.response.status === 403) {
    const matches = await queryEvidence(reconcile.id);
    confirmedFalsePositive = matches.some((item) => item.rules.some((rule) => /^942\d+$/.test(rule)) && item.targets.some((target) => target.includes("expression")) && item.blocked);
    if (confirmedFalsePositive) break;
  }
}

const invalid = await send("parser_attack_control", "/api/transactions/reconcile/search", {
  method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ expression: "merchant contains 'x' OR 1=1--' AND amount between 0 and 999999 AND date between 2026-10-01 and 2026-10-31" }),
}, cookie);
const foreign = await send("cross_account_document", "/api/transactions/tx-linh-001", {}, cookie);
const loginInjection = await send("unrelated_login_control", "/api/auth/login", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "' OR '1'='1", password: "invalid" }),
});

const evidence = {};
async function queryEvidence(id) {
  if (!id) return [];
  const response = await fetch(`${elasticsearch}/waf-lab-*/_search`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ size: 100, query: { bool: { should: [
      ...["http.request.id", "transaction.id", "transaction.request.headers.X-Request-ID", "transaction.request.headers.x-request-id", "request.headers.X-Request-ID", "request.headers.x-request-id", "message"].map((field) => ({ match_phrase: { [field]: id } })),
    ], minimum_should_match: 1 } } }),
  }).catch(() => null);
  if (!response?.ok) return [];
  const body = await response.json().catch(() => ({}));
  return (body.hits?.hits || []).map(({ _source }) => {
    const messages = _source.transaction?.messages || [];
    const rules = [...new Set(messages.map((message) => message.data?.id || message.details?.ruleId).filter(Boolean).map(String))];
    const targetMatches = messages.map((message) => message.data?.data || message.details?.data || message.details?.match || "")
      .map((match) => String(match).match(/(?:ARGS(?:_POST|_GET)?|REQUEST_BODY):[A-Za-z0-9_.-]+/i)?.[0])
      .filter(Boolean);
    return {
      dataset: _source.event?.dataset,
      rules,
      targets: [...new Set(targetMatches)],
      blocked: Boolean(_source.transaction?.is_interrupted || _source.portal?.blocked || Number(_source.http?.response?.status_code) === 403),
      status: _source.http?.response?.status_code,
    };
  });
}

await Promise.all(results.map(async (row) => {
  evidence[row.label] = [];
  for (let attempt = 0; attempt < 5 && !evidence[row.label].length; attempt++) {
    evidence[row.label] = await queryEvidence(row.request_id);
    if (!evidence[row.label].length) await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}));

const report = {
  stage,
  tested_at: new Date().toISOString(),
  edge_host: host,
  valid_expression: expression,
  results,
  evidence,
  interpretation: {
    valid_reconciliation: stage === "before" ? "Expected HTTP 403 before the exception, with Coraza rule and target evidence." : stage === "after" ? "Expected HTTP 200 after the scoped exception." : "Expected HTTP 403 after revoking the exception.",
    parser_control: "Expected application HTTP 400 or WAF HTTP 403; parser rejects unsupported syntax and scopes all DB reads to the session account.",
    cross_account_document: "Expected HTTP 404 for a record owned by another demo account.",
    unrelated_login_control: "Expected WAF HTTP 403 or application HTTP 401; no authentication should be granted.",
  },
};
const outputDir = process.env.FINANCE_RESULTS_DIR || "../runtime/results";
await mkdir(outputDir, { recursive: true });
const outputFile = join(outputDir, `finance-tuning-${stage}-${Date.now()}.json`);
await writeFile(outputFile, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o640 });
console.log(JSON.stringify({ ...report, output_file: outputFile }, null, 2));

const validExpected = stage === "after" ? reconcile.response.status === 200 : reconcile.response.status === 403;
if (!validExpected) process.exitCode = 2;
if (stage !== "after" && !confirmedFalsePositive) process.exitCode = 4;
if ([200, 201, 204].includes(invalid.response.status) || [200, 201, 204].includes(foreign.response.status) || [200, 201, 204].includes(loginInjection.response.status)) process.exitCode = 3;
