import Link from "next/link";

const transactions = [
  { date: "29/09/2026", title: "Lương tháng 9 · Northstar Demo", amount: "+ 48.000.000 ₫", kind: "in" },
  { date: "28/09/2026", title: "Cà phê Sông Xanh", amount: "− 85.000 ₫", kind: "out" },
  { date: "26/09/2026", title: "Chuyển tiền · Nguyễn An", amount: "− 2.500.000 ₫", kind: "out" },
  { date: "24/09/2026", title: "Hoàn tiền mua sắm", amount: "+ 320.000 ₫", kind: "in" }
];

export default function Home() {
  return <main className="shell">
    <header className="topbar"><Link className="brand" href="/">✦ Northstar <span>DEMO BANK</span></Link><div className="status"><i/> Môi trường thực hành cục bộ <a href="/login">Đăng nhập demo</a></div></header>
    <section className="hero"><div><p className="eyebrow">TÀI CHÍNH CÁ NHÂN · LAB WAF</p><h1>Quản lý tiền<br/><em>theo cách của bạn.</em></h1><p className="lead">Một không gian ngân hàng mô phỏng với số dư, giao dịch và chuyển khoản giả lập. Không kết nối thanh toán thật.</p><a className="primary" href="/login">Mở tài khoản demo <span>→</span></a></div><div className="card-art"><div className="card-head">NORTHSTAR <b>✦</b></div><div className="chip"/><div className="card-number">•••• &nbsp; •••• &nbsp; •••• &nbsp; 2048</div><div className="card-foot"><span>NGUYỄN MINH AN</span><span>DEMO ONLY</span></div><div className="glow"/></div></section>
    <section className="stats"><div><small>SỐ DƯ KHẢ DỤNG</small><strong>84.560.000 <b>₫</b></strong><span className="trend">↗ 12,8% <i>so với tháng trước</i></span></div><div className="stat-note"><span className="round-icon">↗</span><div><strong>Chuyển tiền dễ dàng</strong><p>Thử luồng chuyển khoản giả lập trong lab.</p><a href="/dashboard">Xem tài khoản demo →</a></div></div></section>
    <section className="activity"><div className="section-heading"><div><p className="eyebrow">TÀI KHOẢN · •••• 2048</p><h2>Giao dịch gần đây</h2></div><a href="/dashboard">Xem tất cả →</a></div><div className="transactions">{transactions.map((tx) => <div className="transaction" key={tx.title}><span className={`tx-icon ${tx.kind}`}>{tx.kind === "in" ? "↓" : "↗"}</span><div className="tx-title"><strong>{tx.title}</strong><small>{tx.date}</small></div><strong className={tx.kind}>{tx.amount}</strong></div>)}</div></section>
    <section className="lab-note"><span>⌁</span><div><strong>Đây là website phục vụ học tập</strong><p>Những endpoint có nhãn “LAB” mô phỏng lỗ hổng để quan sát WAF. Chỉ kiểm thử trên stack local này.</p></div></section>
    <footer>Northstar Demo Bank <span>·</span> Dữ liệu giả lập <span>·</span> WAF learning lab</footer>
  </main>;
}
