import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

// Deliberately has no CSRF token or authenticated owner check. It only returns
// a fabricated result and never changes an account or calls a payment service.
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const amount = Math.max(0, Math.min(Number(body.amount) || 0, 10_000_000));
  await logEvent(request, "csrf_simulation", "fake_transfer_accepted", { amount, recipient: String(body.recipient ?? "DEMO") });
  return NextResponse.json({ lab: "SIMULATED_CSRF", accepted: true, amount, transaction_id: "LAB-TX-0001" });
}
