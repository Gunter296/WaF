import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

export async function GET(request: NextRequest) {
  const path = request.nextUrl.searchParams.get("path") ?? "";
  const traversal = path.includes("..") || path.startsWith("/");
  await logEvent(request, "path_simulation", traversal ? "traversal_marker" : "fixture_read", { requested_path: path });
  return NextResponse.json({ lab: "SIMULATED_PATH_TRAVERSAL", requested_path: path, contents: traversal ? "LAB_PATH_MARKER · chỉ là chuỗi giả" : "LAB_DEMO_STATEMENT" });
}
