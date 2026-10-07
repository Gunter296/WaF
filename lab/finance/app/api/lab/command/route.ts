import { NextRequest, NextResponse } from "next/server";
import { logEvent } from "../../../../lib/log";

// Safe command-injection fixture. The supplied string is only classified and
// logged; this endpoint never passes input to a shell or operating system.
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}));
  const payload = String(body.payload ?? "");
  const simulated = /[;&|`]|\$\(|\b(?:echo|curl|wget|sh|bash|powershell|cmd)\b/i.test(payload);
  const marker = simulated ? "LAB_CMDI_MARKER" : "LAB_CMDI_VALID";
  await logEvent(request, "command_injection_simulation", simulated ? "marker_returned" : "valid_input", { simulated, executed: false });
  return NextResponse.json({ lab: "SIMULATED_COMMAND_INJECTION", marker, executed: false });
}
