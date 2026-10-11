import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { AccountNav } from "../../../components/account-nav";
import { pool } from "../../../lib/db";
import { dateTime, money } from "../../../lib/format";
import { currentAccount } from "../../../lib/session";
import { logPageEvent } from "../../../lib/log";

export const dynamic = "force-dynamic";

export default async function TransactionDetail({ params }: { params: Promise<{ id: string }> }) {
  const account = await currentAccount();
  if (!account) {
    await logPageEvent("/transactions/[id]", "transaction_page_view", "unauthenticated");
    redirect("/login");
  }
  const { id } = await params;
  const { rows } = await pool.query(
    `SELECT id, kind, merchant, description, amount::text, created_at, reference
       FROM finance_transactions WHERE id=$1 AND account_id=$2`, [id, account.id],
  );
  const item = rows[0];
  if (!item) {
    await logPageEvent("/transactions/[id]", "transaction_page_view", "not_found", account.id);
    notFound();
  }
  await logPageEvent("/transactions/[id]", "transaction_page_view", "complete", account.id);
  return <main className="shell"><AccountNav name={account.owner_name} role={account.role} /><section className="receipt-page">
    <Link href="/dashboard" className="back-link">← Giao dịch</Link>
    <article className="receipt-sheet"><p className="eyebrow">CHỨNG TỪ GIAO DỊCH GIẢ LẬP</p><h1>{item.merchant}</h1><strong className={`receipt-amount ${Number(item.amount) > 0 ? "positive-text" : ""}`}>{Number(item.amount) > 0 ? "+" : "−"}{money(Math.abs(Number(item.amount)), account.currency)}</strong>
      <dl><div><dt>Trạng thái</dt><dd>Đã ghi nhận trong lab</dd></div><div><dt>Ngày giao dịch</dt><dd>{dateTime(item.created_at)}</dd></div><div><dt>Nội dung</dt><dd>{item.description}</dd></div><div><dt>Mã tham chiếu</dt><dd>{item.reference}</dd></div><div><dt>Tài khoản</dt><dd>{account.account_number}</dd></div></dl>
      <a className="button-link" href={`/api/documents/${encodeURIComponent(item.id)}`} target="_blank">Mở dữ liệu chứng từ</a>
    </article>
  </section></main>;
}
