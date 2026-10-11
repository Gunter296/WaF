import { appendFile, readFile } from "node:fs/promises";
import { headers } from "next/headers";
import type { NextRequest } from "next/server";

async function writeFinanceEvent(requestId: string, method: string, route: string, action: string, outcome: string, accountId: string | undefined, details: Record<string, unknown>) {
  let policyVersion: number | string = "unknown";
  const policyFile = process.env.LAB_POLICY_FILE;
  if (policyFile) {
    try { policyVersion = JSON.parse(await readFile(policyFile, "utf8")).version ?? "unknown"; } catch { /* Keep the event useful if the shared policy is unavailable. */ }
  }
  const event = {
    "@timestamp": new Date().toISOString(),
    event: { dataset: "finance.lab", action, outcome },
    http: { request: { id: requestId || "direct" }, request_method: method },
    url: { path: route },
    user: accountId ? { id: accountId } : undefined,
    lab: { policy_version: policyVersion, ...details },
  };
  const path = process.env.LAB_LOG_FILE;
  if (path) await appendFile(path, `${JSON.stringify(event)}\n`).catch(() => undefined);
}

export async function logEvent(request: NextRequest, action: string, outcome: string, accountIdOrDetails?: string | Record<string, unknown>, details: Record<string, unknown> = {}) {
  const accountId = typeof accountIdOrDetails === "string" ? accountIdOrDetails : undefined;
  const safeDetails = accountIdOrDetails && typeof accountIdOrDetails === "object" ? accountIdOrDetails : details;
  await writeFinanceEvent(request.headers.get("x-request-id") || "direct", request.method, request.nextUrl.pathname, action, outcome, accountId, safeDetails);
}

export async function logPageEvent(route: string, action: string, outcome: string, accountId?: string, details: Record<string, unknown> = {}) {
  const requestHeaders = await headers();
  await writeFinanceEvent(requestHeaders.get("x-request-id") || "direct", "GET", route, action, outcome, accountId, details);
}
