import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const enabled = process.env.FINANCE_TEST_URL && process.env.FINANCE_TEST_EMAIL && process.env.FINANCE_TEST_PASSWORD;

test("migration and seed are repeatable without changing balances or fixture row counts", { skip: !process.env.FINANCE_TEST_PG }, async () => {
  const run = (script) => {
    const result = spawnSync(process.execPath, [`scripts/${script}`], { encoding: "utf8", env: process.env });
    assert.equal(result.status, 0, `${script} should complete successfully`);
  };
  run("migrate.mjs");
  run("seed.mjs");
  const { Pool } = await import("pg");
  const pool = new Pool({ host: process.env.PGHOST, port: Number(process.env.PGPORT || 5432), database: process.env.PGDATABASE, user: process.env.PGUSER, password: process.env.PGPASSWORD });
  try {
    const before = await pool.query("SELECT (SELECT count(*) FROM finance_accounts)::int AS accounts, (SELECT count(*) FROM finance_transactions)::int AS transactions, (SELECT sum(balance)::text FROM finance_accounts) AS balances");
    run("migrate.mjs"); run("seed.mjs");
    const after = await pool.query("SELECT (SELECT count(*) FROM finance_accounts)::int AS accounts, (SELECT count(*) FROM finance_transactions)::int AS transactions, (SELECT sum(balance)::text FROM finance_accounts) AS balances");
    assert.deepEqual(after.rows, before.rows);
    assert.equal(Number(before.rows[0].accounts) >= 3, true);
    assert.equal(Number(before.rows[0].transactions) >= 14, true);
  } finally { await pool.end(); }
});

test("server login, access control, reconcile query and simulated balance update", { skip: !enabled }, async () => {
  const base = process.env.FINANCE_TEST_URL.replace(/\/$/, "");
  const request = (path, options = {}) => fetch(`${base}${path}`, { redirect: "manual", ...options });
  const denied = await request("/api/accounts/me");
  assert.equal(denied.status, 401);
  const invalidLogin = await request("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: process.env.FINANCE_TEST_EMAIL, password: "invalid" }) });
  assert.equal(invalidLogin.status, 401);
  const login = await request("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: process.env.FINANCE_TEST_EMAIL, password: process.env.FINANCE_TEST_PASSWORD }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie") || "";
  assert.match(cookie, /HttpOnly/i);
  assert.doesNotMatch(cookie, /demo-session/);
  const cookieValue = cookie.split(";")[0];
  const headers = { cookie: cookieValue };
  const me = await request("/api/accounts/me", { headers });
  assert.equal(me.status, 200);
  const account = await me.json();
  const beforeBalance = Number(account.balance);
  const example = await request("/api/transactions/reconcile/example", { headers });
  assert.equal(example.status, 200);
  const expression = (await example.json()).expression;
  const validFilter = await request("/api/transactions/reconcile/search", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ expression }) });
  assert.equal(validFilter.status, 200);
  assert.ok((await validFilter.json()).items.length > 0);
  const page = await request("/api/transactions?page=1&limit=5", { headers });
  assert.equal(page.status, 200);
  assert.ok((await page.json()).items.length > 0);
  const foreign = await request("/api/transactions/tx-linh-001", { headers });
  const foreignDocument = await request("/api/documents/tx-linh-001", { headers });
  if (account.email !== "linh.demo@northstar.test") {
    assert.equal(foreign.status, 404);
    assert.equal(foreignDocument.status, 404);
  }
  if (account.email === "an.demo@northstar.test") {
    const beneficiaries = await request("/api/beneficiaries", { headers });
    const people = (await beneficiaries.json()).items;
    const linh = people.find((item) => item.account_number === "NS-3106-4821");
    assert.ok(linh);
    const idempotencyKey = crypto.randomUUID();
    const transferBody = { beneficiary_id: linh.id, amount: 1000, purpose: "Kiểm tra giao dịch lab", idempotency_key: idempotencyKey };
    const transfer = await request("/api/transfers", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(transferBody) });
    assert.equal(transfer.status, 201);
    const firstTransfer = await transfer.json();
    const duplicate = await request("/api/transfers", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify(transferBody) });
    assert.equal(duplicate.status, 200);
    assert.equal((await duplicate.json()).transfer_id, firstTransfer.transfer_id);
    const afterDebit = await (await request("/api/accounts/me", { headers })).json();
    assert.equal(Number(afterDebit.balance), beforeBalance - 1000);
    const secondLogin = await request("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "linh.demo@northstar.test", password: process.env.FINANCE_TEST_PASSWORD }) });
    assert.equal(secondLogin.status, 200);
    const secondCookie = (secondLogin.headers.get("set-cookie") || "").split(";")[0];
    const linhHeaders = { cookie: secondCookie };
    const linhBene = (await (await request("/api/beneficiaries", { headers: linhHeaders })).json()).items.find((item) => item.account_number === account.account_number);
    assert.ok(linhBene);
    const reverse = await request("/api/transfers", { method: "POST", headers: { ...linhHeaders, "content-type": "application/json" }, body: JSON.stringify({ beneficiary_id: linhBene.id, amount: 1000, purpose: "Hoàn tất kiểm tra lab", idempotency_key: crypto.randomUUID() }) });
    assert.equal(reverse.status, 201);
    const restored = await request("/api/accounts/me", { headers });
    assert.equal(Number((await restored.json()).balance), beforeBalance);
    await request("/api/auth/logout", { method: "POST", headers: linhHeaders });
  }
  const badFilter = await request("/api/transactions/reconcile/search", { method: "POST", headers: { ...headers, "content-type": "application/json" }, body: JSON.stringify({ expression: "merchant contains 'x' OR 1=1--' AND amount between 0 and 9 AND date between 2026-10-01 and 2026-10-31" }) });
  assert.equal(badFilter.status, 400);
  const logout = await request("/api/auth/logout", { method: "POST", headers });
  assert.equal(logout.status, 200);
  assert.equal((await request("/api/accounts/me", { headers })).status, 401);
});

test("registration and password change use server credentials and rotate sessions", { skip: !process.env.FINANCE_TEST_URL || !process.env.FINANCE_TEST_PG }, async () => {
  const base = process.env.FINANCE_TEST_URL.replace(/\/$/, "");
  const email = `test-${crypto.randomUUID()}@northstar.test`;
  const password = "Lab-start-12345";
  const changedPassword = "Lab-change-67890";
  const request = (path, options = {}) => fetch(`${base}${path}`, { redirect: "manual", ...options });
  const { Pool } = await import("pg");
  const pool = new Pool({ host: process.env.PGHOST, port: Number(process.env.PGPORT || 5432), database: process.env.PGDATABASE, user: process.env.PGUSER, password: process.env.PGPASSWORD });
  try {
    const registration = await request("/api/auth/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Kiểm thử Tài khoản", email, password, password_confirmation: password }),
    });
    assert.equal(registration.status, 201);
    const registrationCookie = (registration.headers.get("set-cookie") || "").split(";")[0];
    assert.match(registrationCookie, /^lab_session=/);
    assert.match(registration.headers.get("set-cookie") || "", /HttpOnly/i);
    const headers = { cookie: registrationCookie };
    const account = await request("/api/accounts/me", { headers });
    assert.equal(account.status, 200);
    assert.equal((await account.json()).balance, "0");
    const changed = await request("/api/auth/password", {
      method: "POST", headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ current_password: password, new_password: changedPassword, password_confirmation: changedPassword }),
    });
    assert.equal(changed.status, 200);
    const changedCookie = (changed.headers.get("set-cookie") || "").split(";")[0];
    assert.match(changedCookie, /^lab_session=/);
    assert.equal(await (await request("/api/accounts/me", { headers })).status, 401);
    const oldLogin = await request("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password }) });
    assert.equal(oldLogin.status, 401);
    const newLogin = await request("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: changedPassword }) });
    assert.equal(newLogin.status, 200);
  } finally {
    await pool.query("DELETE FROM finance_accounts WHERE email=$1", [email]);
    await pool.end();
  }
});

test("admin role can view the finance overview while regular accounts are redirected", { skip: !process.env.FINANCE_TEST_URL || !process.env.FINANCE_ADMIN_EMAIL || !process.env.FINANCE_ADMIN_PASSWORD }, async () => {
  const base = process.env.FINANCE_TEST_URL.replace(/\/$/, "");
  const login = async (email, password) => {
    const response = await fetch(`${base}/api/auth/login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    return { response, body: await response.json(), cookie: (response.headers.get("set-cookie") || "").split(";")[0] };
  };
  const admin = await login(process.env.FINANCE_ADMIN_EMAIL, process.env.FINANCE_ADMIN_PASSWORD);
  assert.equal(admin.response.status, 200);
  assert.equal(admin.body.role, "admin");
  assert.equal((await fetch(`${base}/admin`, { headers: { cookie: admin.cookie } })).status, 200);
  const user = await login(process.env.FINANCE_TEST_EMAIL, process.env.FINANCE_TEST_PASSWORD);
  assert.equal(user.response.status, 200);
  assert.equal(user.body.role, "user");
  const forbidden = await fetch(`${base}/admin`, { headers: { cookie: user.cookie }, redirect: "manual" });
  assert.equal(forbidden.status, 307);
  assert.equal(forbidden.headers.get("location"), "/dashboard");
});
