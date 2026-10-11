import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../lib/db";
import { currentAccount } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export async function GET(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "transaction_detail", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const { id } = await context.params;
  const { rows } = await pool.query(
    `SELECT id, kind, merchant, description, amount::text, created_at, reference
       FROM finance_transactions WHERE id=$1 AND account_id=$2`, [id, account.id],
  );
  if (!rows[0]) {
    await logEvent(request, "transaction_detail", "not_found", account.id);
    return NextResponse.json({ error: "Không tìm thấy giao dịch." }, { status: 404 });
  }
  await logEvent(request, "transaction_detail", "complete", account.id);
  return NextResponse.json(rows[0], { headers: { "cache-control": "no-store" } });
}
