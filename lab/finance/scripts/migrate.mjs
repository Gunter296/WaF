import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const { Pool } = pg;
const pool = new Pool({
  host: process.env.PGHOST || "postgres",
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || "waflab",
  user: process.env.PGUSER || "waflab",
  password: process.env.PGPASSWORD || "local-lab-only",
});

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");
const lockClient = await pool.connect();
try {
  await lockClient.query("SELECT pg_advisory_lock(87473002)");
  await lockClient.query(`CREATE TABLE IF NOT EXISTS finance_schema_migrations (
    version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  const files = (await readdir(migrationsDir)).filter((file) => /^\d+_[a-z0-9_-]+\.sql$/.test(file)).sort();
  for (const file of files) {
    try {
      await lockClient.query("BEGIN");
      const seen = await lockClient.query("SELECT 1 FROM finance_schema_migrations WHERE version=$1", [file]);
      if (!seen.rowCount) {
        await lockClient.query(await readFile(join(migrationsDir, file), "utf8"));
        await lockClient.query("INSERT INTO finance_schema_migrations(version) VALUES($1)", [file]);
      }
      await lockClient.query("COMMIT");
    } catch (error) {
      await lockClient.query("ROLLBACK").catch(() => undefined);
      throw error;
    }
  }
} finally {
  await lockClient.query("SELECT pg_advisory_unlock(87473002)").catch(() => undefined);
  lockClient.release();
  await pool.end();
}
