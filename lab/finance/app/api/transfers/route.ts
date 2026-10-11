import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { inTransaction } from "../../../lib/db";
import { currentAccount } from "../../../lib/session";
import { logEvent } from "../../../lib/log";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function POST(request: NextRequest) {
  const account = await currentAccount(request);
  if (!account) {
    await logEvent(request, "transfer_simulated", "unauthenticated");
    return NextResponse.json({ error: "Cần đăng nhập." }, { status: 401 });
  }
  const body = await request.json().catch(() => null);
  const beneficiaryId = typeof body?.beneficiary_id === "string" ? body.beneficiary_id.slice(0, 64) : "";
  const amount = Number(body?.amount);
  const purpose = typeof body?.purpose === "string" ? body.purpose.trim() : "";
  const key = typeof body?.idempotency_key === "string" ? body.idempotency_key : "";
  if (!beneficiaryId || !Number.isSafeInteger(amount) || amount < 1000 || amount > 10_000_000 || purpose.length < 3 || purpose.length > 100 || !UUID.test(key)) {
    await logEvent(request, "transfer_simulated", "invalid_input", account.id);
    return NextResponse.json({ error: "Thông tin chuyển khoản chưa hợp lệ." }, { status: 400 });
  }
  try {
    const result = await inTransaction(async (client) => {
      const existing = await client.query("SELECT account_id, transfer_id FROM finance_transfer_requests WHERE idempotency_key=$1", [key]);
      if (existing.rowCount) {
        if (existing.rows[0].account_id !== account.id) throw new Error("Mã yêu cầu đã được sử dụng.");
        const prior = await client.query("SELECT id, amount::text FROM finance_transactions WHERE account_id=$1 AND transfer_id=$2 AND kind='transfer_out'", [account.id, existing.rows[0].transfer_id]);
        return { transfer_id: existing.rows[0].transfer_id, transaction_id: prior.rows[0]?.id, replayed: true };
      }
      const beneficiary = await client.query(
        "SELECT id, display_name, account_number FROM finance_beneficiaries WHERE id=$1 AND account_id=$2", [beneficiaryId, account.id],
      );
      if (!beneficiary.rowCount) throw new Error("Không tìm thấy người thụ hưởng.");
      const destination = await client.query("SELECT id FROM finance_accounts WHERE account_number=$1", [beneficiary.rows[0].account_number]);
      const accountIds = [account.id, ...(destination.rows[0] ? [destination.rows[0].id] : [])].sort();
      const locked = await client.query("SELECT id, balance FROM finance_accounts WHERE id=ANY($1::text[]) ORDER BY id FOR UPDATE", [accountIds]);
      const sender = locked.rows.find((row) => row.id === account.id);
      if (!sender || BigInt(sender.balance) < BigInt(amount)) throw new Error("Số dư khả dụng không đủ.");
      const transferId = randomUUID();
      await client.query("INSERT INTO finance_transfer_requests(idempotency_key, account_id, transfer_id) VALUES($1,$2,$3)", [key, account.id, transferId]);
      const updated = await client.query("UPDATE finance_accounts SET balance=balance-$1 WHERE id=$2 RETURNING balance::text", [amount, account.id]);
      const transactionId = randomUUID();
      const reference = `LAB-${transferId.replaceAll("-", "").slice(0, 16).toUpperCase()}`;
      await client.query(
        `INSERT INTO finance_transactions(id,account_id,transfer_id,kind,merchant,description,amount,created_at,reference)
         VALUES($1,$2,$3,'transfer_out',$4,$5,$6,now(),$7)`,
        [transactionId, account.id, transferId, beneficiary.rows[0].display_name, purpose, -amount, reference],
      );
      if (destination.rows[0]) {
        await client.query("UPDATE finance_accounts SET balance=balance+$1 WHERE id=$2", [amount, destination.rows[0].id]);
        await client.query(
          `INSERT INTO finance_transactions(id,account_id,transfer_id,kind,merchant,description,amount,created_at,reference)
           VALUES($1,$2,$3,'transfer_in',$4,$5,$6,now(),$7)`,
          [randomUUID(), destination.rows[0].id, transferId, account.owner_name, purpose, amount, `${reference}-IN`],
        );
      }
      return { transfer_id: transferId, transaction_id: transactionId, balance: updated.rows[0].balance, replayed: false };
    });
    await logEvent(request, "transfer_simulated", "complete", account.id, { transfer_id: result.transfer_id, replayed: result.replayed });
    return NextResponse.json(result, { status: result.replayed ? 200 : 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Không thể hoàn tất chuyển khoản.";
    const status = message === "Số dư khả dụng không đủ." ? 409 : message.includes("Mã yêu cầu") ? 409 : 400;
    await logEvent(request, "transfer_simulated", "rejected", account.id);
    return NextResponse.json({ error: message }, { status });
  }
}
