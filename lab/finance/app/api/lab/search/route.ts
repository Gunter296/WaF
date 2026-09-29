import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

const fakeTransactions = [
  { owner: "an", description: "Lương tháng 9", amount: 48000000 },
  { owner: "an", description: "Cà phê Sông Xanh", amount: -85000 },
  { owner: "binh", description: "LAB_SQLI_MARKER · giao dịch giả của tài khoản Binh", amount: 123456 }
];

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  const injected = /\bor\s+1\s*=\s*1\b|['"]\s*or\s+['"][^'"]+['"]\s*=\s*['"]/i.test(q);
  const rows = injected ? fakeTransactions : fakeTransactions.filter((item) => item.description.toLowerCase().includes(q.toLowerCase()));
  await logEvent(request, "sqli_simulation", injected ? "marker_returned" : "normal_search");
  return NextResponse.json({ lab: "SIMULATED_SQLI", result: rows });
}
