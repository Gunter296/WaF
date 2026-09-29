import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const name = String(body.name ?? "unnamed");
  await logEvent(request, "upload_simulation", "extension_only_check", { filename: name });
  return NextResponse.json({ lab: "SIMULATED_UPLOAD", filename: name, accepted_by_demo: !name.toLowerCase().endsWith(".exe") });
}

export async function GET(request: NextRequest) {
  await logEvent(request, "upload_simulation", "fixture_probe");
  return NextResponse.json({ lab: "SIMULATED_UPLOAD", hint: "POST JSON {name: ...}" });
}
