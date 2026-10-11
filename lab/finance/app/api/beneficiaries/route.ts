import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../lib/db";
import { currentAccount } from "../../../lib/session";
import { logEvent } from "../../../lib/log";

export async function GET(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "beneficiary_list", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const { rows } = await pool.query(
    `SELECT id, display_name, account_number, bank_name FROM finance_beneficiaries
      WHERE account_id=$1 ORDER BY display_name`, [account.id],
  );
  await logEvent(request, "beneficiary_list", "complete", account.id, { count: rows.length });
  return NextResponse.json({ items: rows }, { headers: { "cache-control": "no-store" } });
}
