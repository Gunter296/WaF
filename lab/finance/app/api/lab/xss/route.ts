import { NextRequest } from "next/server";
import { logEvent } from "../../../../lib/log";

export async function GET(request: NextRequest) {
  const value = request.nextUrl.searchParams.get("value") ?? "LAB_XSS_MARKER";
  await logEvent(request, "xss_simulation", "reflected_html");
  // Intentionally unsafe reflection, available only in this isolated local lab.
  return new Response(`<!doctype html><meta charset="utf-8"><title>LAB simulated XSS</title><p>SIMULATED_XSS: ${value}</p>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}
