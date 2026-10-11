import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../../lib/db";
import { logEvent } from "../../../../../lib/log";
import { parseReconcileFilter } from "../../../../../lib/reconcile-filter.mjs";
import { currentAccount } from "../../../../../lib/session";

const escapeLike = (value: string) => value.replace(/[\\%_]/g, "\\$&");

export async function POST(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "reconcile_search", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const contentType = request.headers.get("content-type")?.toLowerCase() || "";
  const body = contentType.startsWith("application/x-www-form-urlencoded")
    ? Object.fromEntries((await request.formData()).entries())
    : await request.json().catch(() => null);
  let filter;
  try { filter = parseReconcileFilter(body?.expression); }
  catch (error) {
    await logEvent(request, "reconcile_search", "invalid_filter", account.id);
    return NextResponse.json({ error: error instanceof Error ? error.message : "Biểu thức chưa hợp lệ." }, { status: 400 });
  }
  const { rows } = await pool.query(
    `SELECT id, kind, merchant, description, amount::text, created_at, reference
       FROM finance_transactions
      WHERE account_id=$1 AND merchant ILIKE $2 ESCAPE E'\\\\'
        AND abs(amount) BETWEEN $3 AND $4
        AND created_at >= $5::date AND created_at < ($6::date + interval '1 day')
      ORDER BY created_at DESC, id DESC LIMIT 100`,
    [account.id, `%${escapeLike(filter.merchant)}%`, filter.minAmount, filter.maxAmount, filter.from, filter.to],
  );
  await logEvent(request, "reconcile_search", "complete", account.id, { count: rows.length });
  return NextResponse.json({ items: rows }, { headers: { "cache-control": "no-store" } });
}
