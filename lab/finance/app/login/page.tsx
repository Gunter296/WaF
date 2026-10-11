import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "../../components/brand";
import { LoginForm } from "../../components/login-form";
import { currentAccount } from "../../lib/session";
import { logPageEvent } from "../../lib/log";

export const dynamic = "force-dynamic";

export default async function Login() {
  const account = await currentAccount();
  await logPageEvent("/login", "login_page_view", account ? "already_authenticated" : "complete", account?.id);
  if (account) redirect("/dashboard");
  return <main className="auth-page"><header><Brand /></header><section className="auth-layout"><div className="auth-aside"><p className="eyebrow">NORTHSTAR DEMO BANK</p><h1>Quản lý tài khoản của bạn.</h1><p>Đăng nhập vào không gian tài chính mô phỏng để xem hoạt động và thử các giao dịch trong lab.</p><Link href="/">Về trang chủ</Link></div><div className="auth-panel"><p className="eyebrow">TÀI KHOẢN DEMO</p><h2>Đăng nhập</h2><p className="auth-intro">Dùng tài khoản được ghi trong hướng dẫn lab.</p><LoginForm /><p className="auth-switch">Chưa có tài khoản? <Link href="/register">Tạo tài khoản demo</Link></p><p className="auth-safety">Thông tin chỉ được xác minh trên máy chủ lab.</p></div></section></main>;
}
