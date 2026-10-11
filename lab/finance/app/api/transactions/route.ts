import { NextRequest, NextResponse } from "next/server";
import { pool } from "../../../lib/db";
import { currentAccount } from "../../../lib/session";
import { logEvent } from "../../../lib/log";

const escapeLike = (value: string) => value.replace(/[\\%_]/g, "\\$&");

export async function GET(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "transaction_search", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const params = request.nextUrl.searchParams;
  const page = Math.max(1, Math.min(10000, Number(params.get("page")) || 1));
  const limit = Math.max(5, Math.min(25, Number(params.get("limit")) || 10));
  const values: unknown[] = [account.id];
  const conditions = ["account_id=$1"];
  const query = (params.get("query") || "").trim().slice(0, 80);
  if (query) { values.push(`%${escapeLike(query)}%`); conditions.push(`(merchant ILIKE $${values.length} ESCAPE E'\\\\' OR description ILIKE $${values.length} ESCAPE E'\\\\' OR reference ILIKE $${values.length} ESCAPE E'\\\\')`); }
  const kind = params.get("kind") || "";
  if (["salary", "purchase", "refund", "transfer_in", "transfer_out", "bill"].includes(kind)) { values.push(kind); conditions.push(`kind=$${values.length}`); }
  const from = params.get("from");
  const to = params.get("to");
  const validDate = (date: string | null) => {
    if (!date) return false;
    const parsed = new Date(`${date}T00:00:00.000Z`);
    return /^\d{4}-\d{2}-\d{2}$/.test(date) && Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === date;
  };
  if (from && !validDate(from) || to && !validDate(to)) {
    await logEvent(request, "transaction_search", "invalid_date", account.id);
    return NextResponse.json({ error: "Khoảng ngày chưa hợp lệ." }, { status: 400 });
  }
  if (from) { values.push(from); conditions.push(`created_at >= $${values.length}::date`); }
  if (to) { values.push(to); conditions.push(`created_at < ($${values.length}::date + interval '1 day')`); }
  const count = await pool.query(`SELECT count(*)::int AS total FROM finance_transactions WHERE ${conditions.join(" AND ")}`, values);
  values.push(limit, (page - 1) * limit);
  const rows = await pool.query(
    `SELECT id, kind, merchant, description, amount::text, created_at, reference
       FROM finance_transactions WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC, id DESC LIMIT $${values.length - 1} OFFSET $${values.length}`, values,
  );
  await logEvent(request, "transaction_search", "complete", account.id, { count: rows.rowCount });
  return NextResponse.json({ items: rows.rows, page, limit, total: count.rows[0].total }, { headers: { "cache-control": "no-store" } });
}
