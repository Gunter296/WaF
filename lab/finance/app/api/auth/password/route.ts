import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { inTransaction, pool } from "../../../../lib/db";
import { createSession, currentAccount } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "password_change", "unauthenticated");
    return NextResponse.json({ error: "Vui lòng đăng nhập lại." }, { status: 401, headers: { "cache-control": "no-store" } });
  }
  const body = await request.json().catch(() => null);
  const currentPassword = typeof body?.current_password === "string" ? body.current_password : "";
  const nextPassword = typeof body?.new_password === "string" ? body.new_password : "";
  const confirmation = typeof body?.password_confirmation === "string" ? body.password_confirmation : "";
  if (currentPassword.length > 128 || nextPassword.length < 10 || nextPassword.length > 128 || nextPassword !== confirmation) {
    await logEvent(request, "password_change", "invalid_input", account.id);
    return NextResponse.json({ error: "Mật khẩu mới cần có từ 10 đến 128 ký tự và hai ô xác nhận phải trùng nhau." }, { status: 400, headers: { "cache-control": "no-store" } });
  }
  if (currentPassword === nextPassword) {
    await logEvent(request, "password_change", "unchanged_password", account.id);
    return NextResponse.json({ error: "Mật khẩu mới phải khác mật khẩu hiện tại." }, { status: 400, headers: { "cache-control": "no-store" } });
  }

  const { rows } = await pool.query("SELECT password_salt,password_hash FROM finance_accounts WHERE id=$1", [account.id]);
  const stored = rows[0];
  const supplied = scryptSync(currentPassword || "invalid", stored.password_salt, 64);
  const expected = Buffer.from(stored.password_hash, "hex");
  if (expected.length !== supplied.length || !timingSafeEqual(supplied, expected)) {
    await logEvent(request, "password_change", "current_password_rejected", account.id);
    return NextResponse.json({ error: "Mật khẩu hiện tại chưa đúng." }, { status: 401, headers: { "cache-control": "no-store" } });
  }

  const salt = randomBytes(16).toString("hex");
  const passwordHash = scryptSync(nextPassword, salt, 64).toString("hex");
  await inTransaction(async (client) => {
    await client.query("UPDATE finance_accounts SET password_salt=$1,password_hash=$2 WHERE id=$3", [salt, passwordHash, account.id]);
    await client.query("DELETE FROM finance_sessions WHERE account_id=$1", [account.id]);
  });
  const response = NextResponse.json({ ok: true }, { headers: { "cache-control": "no-store" } });
  await createSession(account.id, request, response);
  await logEvent(request, "password_change", "updated", account.id);
  return response;
}
