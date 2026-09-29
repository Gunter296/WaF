"use client";
import { useState } from "react";
import Link from "next/link";

export default function Login() {
  const [message, setMessage] = useState("");
  return <main className="login-shell"><Link className="brand" href="/">✦ Northstar <span>DEMO BANK</span></Link><section className="login-card"><p className="eyebrow">TÀI KHOẢN THỰC HÀNH</p><h1>Chào mừng trở lại</h1><p className="muted">Đăng nhập bằng thông tin giả lập bên dưới.</p><form onSubmit={(e) => { e.preventDefault(); document.cookie = "lab-session=demo-session; path=/; SameSite=Lax"; window.location.href = "/dashboard"; }}><label>Email<input type="email" defaultValue="an.demo@northstar.test" required/></label><label>Mật khẩu<input type="password" defaultValue="demo1234" required/></label><button className="primary" type="submit">Đăng nhập an toàn <span>→</span></button></form><p className="demo-creds">DEMO: an.demo@northstar.test · demo1234</p><p className="message">{message}</p></section><p className="login-foot">Local lab · Không sử dụng mật khẩu thật</p></main>;
}
