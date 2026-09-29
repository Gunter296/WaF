import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email ?? "");
  const password = String(body.password ?? "");
  const success = email === "an.demo@northstar.test" && password === "demo1234";
  await logEvent(request, "login_simulation", success ? "demo_success" : "demo_failure", { username: email });
  return NextResponse.json({ lab: "SIMULATED_LOGIN", success }, { status: success ? 200 : 401 });
}
