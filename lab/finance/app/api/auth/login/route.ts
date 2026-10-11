import { scryptSync, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../lib/db";
import { createSession } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => null);
  const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body?.password === "string" ? body.password : "";
  if (email.length > 254 || password.length > 128) {
    await logEvent(request, "login", "invalid_input");
    return NextResponse.json({ error: "Thông tin đăng nhập không hợp lệ." }, { status: 400 });
  }
  const { rows } = await pool.query(
    "SELECT id, role, password_salt, password_hash FROM finance_accounts WHERE email=$1", [email],
  );
  const account = rows[0];
  const supplied = scryptSync(password || "invalid", account?.password_salt || "northstar-invalid-login", 64);
  const expected = account?.password_hash ? Buffer.from(account.password_hash, "hex") : Buffer.alloc(64);
  const valid = Boolean(account && expected.length === supplied.length && timingSafeEqual(supplied, expected));
  if (!valid) {
    await logEvent(request, "login", "rejected");
    return NextResponse.json({ error: "Email hoặc mật khẩu chưa đúng." }, { status: 401, headers: { "cache-control": "no-store" } });
  }
  const response = NextResponse.json({ ok: true, role: account.role }, { headers: { "cache-control": "no-store" } });
  await createSession(account.id, request, response);
  await logEvent(request, "login", "accepted", account.id);
  return response;
}
