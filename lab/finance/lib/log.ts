import { appendFile } from "node:fs/promises";
import { NextRequest } from "next/server";

export async function logEvent(request: NextRequest, action: string, outcome: string, extra: Record<string, unknown> = {}) {
  const entry = {
    "@timestamp": new Date().toISOString(),
    event: { dataset: "finance.lab", action, outcome },
    http: { request: { id: request.headers.get("x-request-id") ?? "direct" }, request_method: request.method },
    url: { path: request.nextUrl.pathname },
    lab: extra
  };
  const path = process.env.LAB_LOG_FILE;
  if (path) await appendFile(path, `${JSON.stringify(entry)}\n`).catch(() => undefined);
}
