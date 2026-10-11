import { randomBytes, randomInt, randomUUID, scryptSync } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../../lib/db";
import { createSession } from "../../../../lib/session";
import { logEvent } from "../../../../lib/log";

export const dynamic = "force-dynamic";

function validEmail(value: string) {
  return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
}

export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => null);
  const name = typeof body?.name === "string" ? body.name.trim().replace(/\s+/g, " ") : "";
  const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body?.password === "string" ? body.password : "";
  const confirmation = typeof body?.password_confirmation === "string" ? body.password_confirmation : "";
  if (name.length < 2 || name.length > 100 || /[\u0000-\u001f]/.test(name) || !validEmail(email) || password.length < 10 || password.length > 128 || password !== confirmation) {
    await logEvent(request, "account_registration", "invalid_input");
    return NextResponse.json({ error: "Vui lòng kiểm tra họ tên, email và mật khẩu tối thiểu 10 ký tự." }, { status: 400, headers: { "cache-control": "no-store" } });
  }

  const salt = randomBytes(16).toString("hex");
  const passwordHash = scryptSync(password, salt, 64).toString("hex");
  const accountId = `acct-${randomUUID()}`;
  let accountNumber = "";
  let inserted = false;
  for (let attempt = 0; attempt < 3 && !inserted; attempt++) {
    accountNumber = `NS-${randomInt(100000, 1000000)}-${randomInt(1000, 10000)}`;
    try {
      await pool.query(
        `INSERT INTO finance_accounts(id,email,owner_name,account_number,password_salt,password_hash,balance)
         VALUES($1,$2,$3,$4,$5,$6,0)`,
        [accountId, email, name, accountNumber, salt, passwordHash],
      );
      inserted = true;
    } catch (error) {
      if ((error as { code?: string }).code === "23505" && attempt < 2) {
        const duplicateEmail = await pool.query("SELECT 1 FROM finance_accounts WHERE email=$1", [email]);
        if (duplicateEmail.rowCount) {
          await logEvent(request, "account_registration", "email_conflict");
          return NextResponse.json({ error: "Email này đã được đăng ký." }, { status: 409, headers: { "cache-control": "no-store" } });
        }
        continue;
      }
      if ((error as { code?: string }).code === "23505") {
        await logEvent(request, "account_registration", "conflict");
        return NextResponse.json({ error: "Không thể tạo tài khoản lúc này. Vui lòng thử lại." }, { status: 409, headers: { "cache-control": "no-store" } });
      }
      throw error;
    }
  }

  const response = NextResponse.json({ ok: true }, { status: 201, headers: { "cache-control": "no-store" } });
  await createSession(accountId, request, response);
  await logEvent(request, "account_registration", "created", accountId);
  return response;
}
