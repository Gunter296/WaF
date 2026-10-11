import { redirect } from "next/navigation";
import { AccountNav } from "../../components/account-nav";
import { ReconcileSearch, TransactionBrowser } from "../../components/transaction-browser";
import { TransferForm } from "../../components/transfer-form";
import { pool } from "../../lib/db";
import { accountSummary } from "../../lib/finance";
import { money } from "../../lib/format";
import { currentAccount } from "../../lib/session";
import { logPageEvent } from "../../lib/log";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  const account = await currentAccount();
  if (!account) {
    await logPageEvent("/dashboard", "dashboard_view", "unauthenticated");
    redirect("/login");
  }
  const [summary, transactions, beneficiaries] = await Promise.all([
    accountSummary(account),
    pool.query(`SELECT id, kind, merchant, description, amount::text, created_at, reference
                  FROM finance_transactions WHERE account_id=$1 ORDER BY created_at DESC, id DESC LIMIT 10`, [account.id]),
    pool.query(`SELECT id, display_name, account_number, bank_name FROM finance_beneficiaries
                  WHERE account_id=$1 ORDER BY display_name`, [account.id]),
  ]);
  const firstName = account.owner_name.split(" ").at(-1) || account.owner_name;
  await logPageEvent("/dashboard", "dashboard_view", "complete", account.id, { transaction_count: summary.totals.transaction_count, beneficiary_count: beneficiaries.rowCount });
  return <main className="shell">
    <AccountNav name={account.owner_name} role={account.role} />
    <section className="dashboard-heading"><div><p className="eyebrow">TỔNG QUAN TÀI KHOẢN</p><h1>Chào {firstName}</h1><p>Thông tin tài khoản được cập nhật từ dữ liệu lab.</p></div><time dateTime={new Date().toISOString()}>{new Intl.DateTimeFormat("vi-VN", { dateStyle: "full", timeZone: "Asia/Ho_Chi_Minh" }).format(new Date())}</time></section>
    <section className="dashboard-grid">
      <div className="balance-card"><div><span>Số dư khả dụng</span><strong>{money(account.balance, account.currency)}</strong><small>{account.account_number} <span>·</span> Tài khoản thanh toán</small></div><div className="balance-footer"><span>{summary.totals.transaction_count} giao dịch</span><span>{account.currency}</span></div></div>
      <div className="account-activity"><div className="activity-metric"><span>Tiền vào tháng này</span><strong>{money(summary.monthly.incoming, account.currency)}</strong></div><div className="activity-metric"><span>Tiền ra tháng này</span><strong>{money(Math.abs(Number(summary.monthly.outgoing)), account.currency)}</strong></div><div className="activity-metric"><span>Người thụ hưởng</span><strong>{beneficiaries.rowCount}</strong></div></div>
    </section>
    <section className="dashboard-layout"><div className="dashboard-main">
      <TransactionBrowser initial={{ items: transactions.rows, page: 1, limit: 10, total: Number(summary.totals.transaction_count) }} />
      <ReconcileSearch />
    </div><aside className="dashboard-side"><TransferForm beneficiaries={beneficiaries.rows} /><section className="beneficiary-list"><div className="section-title"><div><h2>Người thụ hưởng</h2><p>Tài khoản đã lưu</p></div></div>{beneficiaries.rows.length ? beneficiaries.rows.map((bene) => <div className="beneficiary-row" key={bene.id}><span className="beneficiary-avatar">{bene.display_name.slice(0, 1)}</span><div><strong>{bene.display_name}</strong><span>{bene.bank_name} · {bene.account_number}</span></div></div>) : <div className="empty-state"><span>Danh sách trống.</span></div>}</section></aside></section>
    <footer className="site-footer"><span>Northstar Demo Bank</span><span>Giao dịch chỉ thay đổi dữ liệu giả lập.</span></footer>
  </main>;
}
