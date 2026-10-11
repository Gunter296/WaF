import Link from "next/link";
import { redirect } from "next/navigation";
import { AccountNav } from "../../../components/account-nav";
import { PasswordForm } from "../../../components/password-form";
import { currentAccount } from "../../../lib/session";
import { logPageEvent } from "../../../lib/log";

export const dynamic = "force-dynamic";

export default async function SecuritySettings() {
  const account = await currentAccount();
  if (!account) {
    await logPageEvent("/settings/security", "security_settings_view", "unauthenticated");
    redirect("/login");
  }
  await logPageEvent("/settings/security", "security_settings_view", "complete", account.id);
  return <main className="shell"><AccountNav name={account.owner_name} role={account.role} /><section className="account-detail security-settings"><Link className="back-link" href="/account/private">Thông tin tài khoản</Link><p className="eyebrow">BẢO MẬT TÀI KHOẢN</p><h1>Đổi mật khẩu</h1><p className="auth-intro">Xác minh mật khẩu hiện tại trước khi đặt mật khẩu mới.</p><PasswordForm /></section></main>;
}
