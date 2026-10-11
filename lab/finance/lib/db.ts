import { Pool } from "pg";

const globalForPool = globalThis as typeof globalThis & { financePool?: Pool };

export const pool = globalForPool.financePool ?? new Pool({
  host: process.env.PGHOST || "postgres",
  port: Number(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || "waflab",
  user: process.env.PGUSER || "waflab",
  password: process.env.PGPASSWORD || "local-lab-only",
  max: 8,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 3_000,
});

if (process.env.NODE_ENV !== "production") globalForPool.financePool = pool;

export async function inTransaction<T>(work: (client: import("pg").PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
