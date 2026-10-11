import { NextRequest, NextResponse } from "next/server";
import { currentAccount, clearSessionCookie, deleteSession } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export async function POST(request: NextRequest) {
  const account = await currentAccount(request);
  await deleteSession(request);
  const response = NextResponse.json({ ok: true }, { headers: { "cache-control": "no-store" } });
  clearSessionCookie(response);
  await logEvent(request, "logout", "accepted", account?.id);
  return response;
}
