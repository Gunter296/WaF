import { NextRequest, NextResponse } from "next/server";

// Authorization for finance data is enforced by the server routes and session lookup.
export function proxy(_request: NextRequest) {
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|healthz).*)"]
};
