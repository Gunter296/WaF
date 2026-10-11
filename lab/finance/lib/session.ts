import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { pool } from "./db";

const COOKIE = "lab_session";
const MAX_AGE = 60 * 60 * 12;
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

export type Account = {
  id: string;
  email: string;
  owner_name: string;
  account_number: string;
  balance: string;
  currency: string;
  role: "user" | "admin";
};

export async function currentAccount(request?: NextRequest): Promise<Account | null> {
  const token = request
    ? request.cookies.get(COOKIE)?.value
    : (await cookies()).get(COOKIE)?.value;
  if (!token || token.length > 128) return null;
  const { rows } = await pool.query<Account>(
    `SELECT a.id, a.email, a.owner_name, a.account_number, a.balance::text, a.currency, a.role
       FROM finance_sessions s JOIN finance_accounts a ON a.id = s.account_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [digest(token)],
  );
  return rows[0] ?? null;
}

export async function createSession(accountId: string, request: NextRequest, response: NextResponse) {
  const token = randomBytes(32).toString("base64url");
  await pool.query(
    "INSERT INTO finance_sessions(token_hash, account_id, expires_at) VALUES ($1, $2, now() + interval '12 hours')",
    [digest(token), accountId],
  );
  const forwardedProto = request.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim();
  response.cookies.set(COOKIE, token, {
    httpOnly: true,
    secure: forwardedProto === "https" || request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: MAX_AGE,
  });
}

export async function deleteSession(request: NextRequest) {
  const token = request.cookies.get(COOKIE)?.value;
  if (token && token.length <= 128) await pool.query("DELETE FROM finance_sessions WHERE token_hash = $1", [digest(token)]);
}

export function clearSessionCookie(response: NextResponse) {
  response.cookies.set(COOKIE, "", { httpOnly: true, sameSite: "lax", path: "/", maxAge: 0 });
}
