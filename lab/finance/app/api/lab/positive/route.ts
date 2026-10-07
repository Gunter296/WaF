import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

const allowedKeys = new Set(["action", "reference", "filename"]);

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => null);
  const keys = body && typeof body === "object" && !Array.isArray(body) ? Object.keys(body) : [];
  const valid = Boolean(
    body && typeof body === "object" && !Array.isArray(body) &&
    keys.length === allowedKeys.size && keys.every((key) => allowedKeys.has(key)) &&
    body.action === "lookup" && body.reference === "LAB-1001" &&
    typeof body.filename === "string" && /\.(pdf|txt)$/i.test(body.filename)
  );
  await logEvent(request, "positive_security_fixture", valid ? "allowed" : "application_rejected", { keys });
  if (!valid) return NextResponse.json({ lab: "POSITIVE_SECURITY_FIXTURE", accepted: false }, { status: 400 });
  return NextResponse.json({ lab: "POSITIVE_SECURITY_FIXTURE", accepted: true, marker: "LAB_POSITIVE_ALLOWED" });
}
