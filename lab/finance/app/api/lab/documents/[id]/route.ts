import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../../lib/log";

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // Deliberately does not check owner. Only fabricated statements are returned.
  await logEvent(request, "idor_simulation", "statement_read", { document_id: id });
  return NextResponse.json({ lab: "SIMULATED_IDOR", document_id: id, owner: id === "1001" ? "an.demo" : "binh.demo", contents: "LAB_FAKE_STATEMENT · số dư giả · không có dữ liệu cá nhân" });
}
