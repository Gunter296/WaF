import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../../lib/db";
import { currentAccount } from "../../../../../lib/session";
import { logEvent } from "../../../../../lib/log";

export async function GET(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "reconcile_example", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const { rows } = await pool.query(
    `SELECT merchant, abs(amount)::bigint AS amount, date_trunc('month', created_at)::date AS month_start,
            (date_trunc('month', created_at) + interval '1 month - 1 day')::date AS month_end
       FROM finance_transactions WHERE account_id=$1 AND merchant='O''Connor Market'
        AND abs(amount) BETWEEN 50000 AND 250000 ORDER BY created_at DESC LIMIT 1`, [account.id],
  );
  const example = rows[0];
  if (!example) return NextResponse.json({ error: "Không có giao dịch ví dụ phù hợp trong tài khoản." }, { status: 404 });
  await logEvent(request, "reconcile_example", "complete", account.id);
  return NextResponse.json({ expression: `merchant contains 'O''Connor Market' AND amount between 50000 and 250000 AND date between ${String(example.month_start).slice(0, 10)} and ${String(example.month_end).slice(0, 10)}` });
}
