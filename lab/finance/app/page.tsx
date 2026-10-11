import Link from "next/link";
import { AccountNav } from "../components/account-nav";
import { accountSummary } from "../lib/finance";
import { money } from "../lib/format";
import { logPageEvent } from "../lib/log";
import { currentAccount } from "../lib/session";

export const dynamic = "force-dynamic";

export default async function Home() {
  const account = await currentAccount();
  const summary = account ? await accountSummary(account) : null;
  await logPageEvent("/", "home_view", "complete", account?.id, { authenticated: Boolean(account) });
  return <main className="shell">
    <AccountNav name={account?.owner_name} role={account?.role} />
    {summary && account ? <>
      <section className="home-welcome"><div><p className="eyebrow">TÀI KHOẢN CỦA BẠN</p><h1>Xin chào, {account.owner_name.split(" ").at(-1)}.</h1><p>Số dư và hoạt động mới nhất được đồng bộ từ dữ liệu lab.</p></div><Link className="button-link" href="/dashboard">Mở tổng quan</Link></section>
      <section className="balance-feature"><div><span>Số dư khả dụng</span><strong>{money(account.balance, account.currency)}</strong><small>{account.account_number}</small></div><div className="balance-mark" aria-hidden="true">NS</div></section>
      <section className="content-section"><div className="section-title"><div><h2>Giao dịch gần đây</h2><p>Thông tin mới nhất trong tài khoản.</p></div></div>
        {summary.transactions.map((tx) => <div className="transaction-row" key={tx.id}><span className="transaction-mark">{tx.kind === "salary" ? "+" : "↗"}</span><div className="transaction-copy"><strong>{tx.merchant}</strong><span>{tx.description}</span></div><strong className="transaction-amount">{Number(tx.amount) > 0 ? "+" : "−"}{money(Math.abs(Number(tx.amount)), account.currency)}</strong></div>)}
      </section>
    </> : <>
      <section className="home-hero"><div className="hero-copy"><p className="eyebrow">NORTHSTAR DEMO BANK</p><h1>Tài chính cá nhân, trong một không gian thực hành.</h1><p>Số dư, giao dịch và chuyển khoản mô phỏng được lưu trong dữ liệu lab. Không kết nối dịch vụ thanh toán thật.</p><Link className="button-link" href="/login">Đăng nhập demo <span aria-hidden="true">→</span></Link></div>
        <div className="hero-art" aria-label="Thẻ tài khoản giả lập"><div className="art-top"><span>Northstar</span><b>NS</b></div><div className="art-chip"/><div className="art-number">•••• &nbsp; •••• &nbsp; •••• &nbsp; ••••</div><div className="art-bottom"><span>TÀI KHOẢN MÔ PHỎNG</span><span>VND</span></div></div></section>
      <section className="home-note"><strong>Dành cho thực hành WAF</strong><span>Dữ liệu giả lập. Đăng nhập để mở các tính năng tài khoản.</span></section>
    </>}
    <footer className="site-footer"><span>Northstar Demo Bank</span><span>Dữ liệu giả lập, chỉ dùng trong lab</span></footer>
  </main>;
}
