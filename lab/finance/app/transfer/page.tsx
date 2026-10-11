import Link from "next/link";
import { redirect } from "next/navigation";
import { AccountNav } from "../../components/account-nav";
import { TransferForm } from "../../components/transfer-form";
import { pool } from "../../lib/db";
import { currentAccount } from "../../lib/session";
import { logPageEvent } from "../../lib/log";

export const dynamic = "force-dynamic";

export default async function Transfer() {
  const account = await currentAccount();
  if (!account) {
    await logPageEvent("/transfer", "transfer_page_view", "unauthenticated");
    redirect("/login");
  }
  const { rows } = await pool.query("SELECT id, display_name, account_number, bank_name FROM finance_beneficiaries WHERE account_id=$1 ORDER BY display_name", [account.id]);
  await logPageEvent("/transfer", "transfer_page_view", "complete", account.id, { beneficiary_count: rows.length });
  return <main className="shell"><AccountNav name={account.owner_name} role={account.role} /><section className="transfer-page"><Link className="back-link" href="/dashboard">← Tổng quan</Link><TransferForm beneficiaries={rows} /><p className="auth-safety">Đây là giao dịch giả lập. Không có ngân hàng hoặc dịch vụ thanh toán bên ngoài được gọi.</p></section></main>;
}
