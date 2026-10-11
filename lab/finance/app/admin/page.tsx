import { redirect } from "next/navigation";
import { AccountNav } from "../../components/account-nav";
import { dateTime, money } from "../../lib/format";
import { pool } from "../../lib/db";
import { logPageEvent } from "../../lib/log";
import { currentAccount } from "../../lib/session";

export const dynamic = "force-dynamic";

export default async function AdminPage() {
  const admin = await currentAccount();
  if (!admin) {
    await logPageEvent("/admin", "admin_overview_view", "unauthenticated");
    redirect("/login");
  }
  if (admin.role !== "admin") {
    await logPageEvent("/admin", "admin_overview_view", "forbidden", admin.id);
    redirect("/dashboard");
  }

  const [summary, accounts, transactions] = await Promise.all([
    pool.query(`SELECT count(*)::int AS account_count,
                       (SELECT count(*)::int FROM finance_transactions) AS transaction_count,
                       COALESCE(sum(balance),0)::text AS total_balance
                  FROM finance_accounts`),
    pool.query(`SELECT id, owner_name, email, account_number, balance::text, currency, role, created_at
                  FROM finance_accounts ORDER BY created_at DESC, id`),
    pool.query(`SELECT t.id, a.owner_name, t.kind, t.merchant, t.description, t.amount::text,
                       t.created_at, t.reference
                  FROM finance_transactions t JOIN finance_accounts a ON a.id=t.account_id
                 ORDER BY t.created_at DESC, t.id DESC`),
  ]);
  await logPageEvent("/admin", "admin_overview_view", "complete", admin.id, {
    account_count: accounts.rowCount,
    transaction_count: transactions.rowCount,
  });

  return <main className="shell">
    <AccountNav name={admin.owner_name} role={admin.role} />
    <section className="dashboard-heading"><div><p className="eyebrow">QUẢN TRỊ TÀI CHÍNH</p><h1>Tổng quan hệ thống</h1><p>Dữ liệu của các tài khoản demo trong lab.</p></div><span className="admin-role">Quản trị viên</span></section>
    <section className="admin-metrics" aria-label="Thống kê hệ thống">
      <div><span>Tài khoản</span><strong>{summary.rows[0].account_count}</strong></div>
      <div><span>Giao dịch</span><strong>{summary.rows[0].transaction_count}</strong></div>
      <div><span>Tổng số dư mô phỏng</span><strong>{money(summary.rows[0].total_balance)}</strong></div>
    </section>
    <section className="admin-panel"><div className="section-title"><div><h2>Tài khoản</h2><p>Thông tin và quyền truy cập trong finance lab.</p></div></div>
      <div className="admin-table-wrap"><table className="admin-table"><caption className="sr-only">Danh sách toàn bộ tài khoản finance</caption><thead><tr><th>Chủ tài khoản</th><th>Email</th><th>Số tài khoản</th><th>Số dư</th><th>Vai trò</th><th>Ngày tạo</th></tr></thead><tbody>
        {accounts.rows.map((row) => <tr key={row.id}><td>{row.owner_name}</td><td>{row.email}</td><td>{row.account_number}</td><td>{money(row.balance, row.currency)}</td><td>{row.role === "admin" ? "Quản trị viên" : "Người dùng"}</td><td>{dateTime(row.created_at)}</td></tr>)}
      </tbody></table></div>
    </section>
    <section className="admin-panel"><div className="section-title"><div><h2>Lịch sử giao dịch</h2><p>{transactions.rowCount} giao dịch giả lập trên mọi tài khoản.</p></div></div>
      <div className="admin-table-wrap"><table className="admin-table"><caption className="sr-only">Lịch sử giao dịch của toàn bộ tài khoản demo</caption><thead><tr><th>Thời gian</th><th>Chủ tài khoản</th><th>Đơn vị giao dịch</th><th>Nội dung</th><th>Số tiền</th><th>Mã tham chiếu</th></tr></thead><tbody>
        {transactions.rows.map((row) => <tr key={row.id}><td>{dateTime(row.created_at)}</td><td>{row.owner_name}</td><td>{row.merchant}</td><td>{row.description}</td><td className={Number(row.amount) > 0 ? "positive-text" : ""}>{Number(row.amount) > 0 ? "+" : "−"}{money(Math.abs(Number(row.amount)))}</td><td>{row.reference}</td></tr>)}
      </tbody></table></div>
    </section>
    <p className="auth-safety admin-note">Trang này chỉ hiển thị dữ liệu giả lập. Không có giao dịch hoặc số dư thật.</p>
  </main>;
}
