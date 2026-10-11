import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../lib/db";
import { currentAccount } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export async function GET(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "receipt_view", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const { id } = await context.params;
  const { rows } = await pool.query(
    `SELECT t.id, t.reference, t.merchant, t.description, t.amount::text, t.created_at, t.kind,
            a.owner_name, a.account_number
       FROM finance_transactions t JOIN finance_accounts a ON a.id=t.account_id
      WHERE t.id=$1 AND t.account_id=$2`, [id, account.id],
  );
  if (!rows[0]) {
    await logEvent(request, "receipt_view", "not_found", account.id);
    return NextResponse.json({ error: "Không tìm thấy chứng từ." }, { status: 404 });
  }
  await logEvent(request, "receipt_view", "complete", account.id);
  return NextResponse.json({ document_type: "Chứng từ giao dịch giả lập", currency: "VND", ...rows[0] }, { headers: { "cache-control": "no-store" } });
}
