import "server-only";
import { pool } from "./db";
import type { Account } from "./session";
import type { Transaction } from "./format";
export type { Transaction } from "./format";

export async function accountSummary(account: Account) {
  const [{ rows: [totals] }, { rows: transactions }] = await Promise.all([
    pool.query(
      `SELECT count(*)::int AS transaction_count,
              count(*) FILTER (WHERE amount > 0)::int AS incoming_count,
              count(*) FILTER (WHERE amount < 0)::int AS outgoing_count
         FROM finance_transactions WHERE account_id=$1`, [account.id],
    ),
    pool.query<Transaction>(
      `SELECT id, kind, merchant, description, amount::text, created_at, reference
         FROM finance_transactions WHERE account_id=$1 ORDER BY created_at DESC, id DESC LIMIT 5`, [account.id],
    ),
  ]);
  const { rows: [monthly] } = await pool.query(
    `SELECT COALESCE(sum(amount) FILTER (WHERE amount > 0), 0)::text AS incoming,
            COALESCE(sum(amount) FILTER (WHERE amount < 0), 0)::text AS outgoing
       FROM finance_transactions WHERE account_id=$1
        AND created_at >= date_trunc('month', now())`, [account.id],
  );
  return { account, totals, monthly, transactions };
}
