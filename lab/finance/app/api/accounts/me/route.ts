import { NextRequest, NextResponse } from "next/server";
import { currentAccount } from "../../../../lib/session";
import { accountSummary } from "../../../../lib/finance";
import { logEvent } from "../../../../lib/log";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "account_summary", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const summary = await accountSummary(account);
  await logEvent(request, "account_summary", "complete", account.id, { transaction_count: summary.totals.transaction_count });
  return NextResponse.json(summary, { headers: { "cache-control": "no-store" } });
}
