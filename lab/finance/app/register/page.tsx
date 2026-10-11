import Link from "next/link";
import { redirect } from "next/navigation";
import { Brand } from "../../components/brand";
import { RegisterForm } from "../../components/register-form";
import { currentAccount } from "../../lib/session";
import { logPageEvent } from "../../lib/log";

export const dynamic = "force-dynamic";

export default async function Register() {
  const account = await currentAccount();
  await logPageEvent("/register", "registration_page_view", account ? "already_authenticated" : "complete", account?.id);
  if (account) redirect("/dashboard");
  return <main className="auth-page"><header><Brand /></header><section className="auth-layout"><div className="auth-aside"><p className="eyebrow">NORTHSTAR DEMO BANK</p><h1>Tạo tài khoản để bắt đầu.</h1><p>Tài khoản mới dùng dữ liệu giả, số dư ban đầu bằng 0 và không liên kết dịch vụ thanh toán.</p><Link href="/login">Đã có tài khoản? Đăng nhập</Link></div><div className="auth-panel"><p className="eyebrow">ĐĂNG KÝ LOCAL</p><h2>Tạo tài khoản demo</h2><p className="auth-intro">Thông tin đăng nhập được xác minh và lưu ở server lab.</p><RegisterForm /><p className="auth-safety">Dùng email và mật khẩu riêng cho môi trường thực hành.</p></div></section></main>;
}
