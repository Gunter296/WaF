import { scryptSync } from "node:crypto";
import pg from "pg";
import { createSeedTransactions } from "../lib/seed-fixtures.mjs";

const { Pool } = pg;
const pool = new Pool({
  host: process.env.PGHOST || "postgres",
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || "waflab",
  user: process.env.PGUSER || "waflab",
  password: process.env.PGPASSWORD || "local-lab-only",
});
const password = process.env.FINANCE_DEMO_PASSWORD || "demo1234";
const adminPassword = process.env.FINANCE_ADMIN_PASSWORD || "admin12345";
const fixtures = [
  { id: "acct-an-2048", email: "an.demo@northstar.test", salt: "northstar-demo-an-v1" },
  { id: "acct-linh-3106", email: "linh.demo@northstar.test", salt: "northstar-demo-linh-v1" },
  { id: "acct-quang-5821", email: "quang.demo@northstar.test", salt: "northstar-demo-quang-v1" },
  { id: "acct-admin-0001", email: "admin@northstar.test", salt: "northstar-demo-admin-v1", password: adminPassword, role: "admin" },
];
try {
  await pool.query(
    `INSERT INTO finance_accounts(id,email,owner_name,account_number,password_salt,password_hash,balance,role)
     VALUES('acct-admin-0001','admin@northstar.test','Quản trị viên Northstar','NS-0000-1001','northstar-demo-admin-v1','',0,'admin')
     ON CONFLICT (id) DO NOTHING`,
  );
  await pool.query("UPDATE finance_accounts SET role='admin' WHERE id='acct-admin-0001'");
  for (const account of fixtures) {
    const hash = scryptSync(account.password || password, account.salt, 64).toString("hex");
    await pool.query(
      "UPDATE finance_accounts SET password_hash=$1 WHERE id=$2 AND password_hash=''",
      [hash, account.id],
    );
  }
  for (const transaction of createSeedTransactions()) {
    await pool.query(
      `INSERT INTO finance_transactions(id, account_id, kind, merchant, description, amount, created_at, reference)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING`,
      [transaction.id, transaction.accountId, transaction.kind, transaction.merchant, transaction.description, transaction.amount, transaction.createdAt, transaction.reference],
    );
  }
  await pool.query("DELETE FROM finance_sessions WHERE expires_at <= now()");
} finally { await pool.end(); }
