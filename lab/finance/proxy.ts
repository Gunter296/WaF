import { NextRequest, NextResponse } from "next/server";

// Deliberately middleware-only authorization fixture for CVE-2026-64642.
// All content is fabricated; the handler does not guard real financial data.
export function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  if (path.includes("/account/private") && request.cookies.get("lab-session")?.value !== "demo-session") {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|healthz).*)"]
};
