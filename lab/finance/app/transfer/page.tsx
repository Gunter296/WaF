"use client";
import Link from "next/link";
import { useState } from "react";

export default function Transfer() {
  const [done, setDone] = useState(false);
  return <main className="login-shell"><Link className="brand" href="/dashboard">✦ Northstar <span>DEMO BANK</span></Link><section className="login-card"><p className="eyebrow">CHUYỂN KHOẢN MÔ PHỎNG</p><h1>Chuyển tiền</h1><p className="muted">Không có khoản tiền nào được chuyển thật.</p>{done ? <div className="success">✓ Giao dịch demo đã được ghi nhận trong phiên này.<p><Link href="/dashboard">Quay về tài khoản →</Link></p></div> : <form onSubmit={async (e) => { e.preventDefault(); await fetch("/api/lab/transfer", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ recipient: "DEMO-0002", amount: 250000 }) }); setDone(true); }}><label>Người nhận<input defaultValue="Nguyễn An" required/></label><label>Tài khoản nhận<input defaultValue="DEMO-0002" required/></label><label>Số tiền (₫)<input type="number" min="1" max="10000000" defaultValue="250000" required/></label><button className="primary" type="submit">Xác nhận demo <span>→</span></button></form>}<p className="demo-creds">Giao dịch chỉ thay đổi giao diện bài lab, không gọi cổng thanh toán.</p></section></main>;
}
