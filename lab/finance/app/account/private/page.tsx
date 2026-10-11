import Link from "next/link";
import { redirect } from "next/navigation";
import { AccountNav } from "../../../components/account-nav";
import { currentAccount } from "../../../lib/session";
import { money } from "../../../lib/format";
import { logPageEvent } from "../../../lib/log";

export const dynamic = "force-dynamic";

export default async function PrivateAccount() {
  const account = await currentAccount();
  if (!account) {
    await logPageEvent("/account/private", "account_detail_view", "unauthenticated");
    redirect("/login");
  }
  await logPageEvent("/account/private", "account_detail_view", "complete", account.id);
  return <main className="shell"><AccountNav name={account.owner_name} role={account.role} /><section className="account-detail"><p className="eyebrow">THÔNG TIN TÀI KHOẢN</p><h1>{account.owner_name}</h1><dl><div><dt>Số tài khoản</dt><dd>{account.account_number}</dd></div><div><dt>Số dư khả dụng</dt><dd>{money(account.balance, account.currency)}</dd></div><div><dt>Email đăng nhập</dt><dd>{account.email}</dd></div></dl><Link className="button-link" href="/dashboard">Quay lại tổng quan</Link></section></main>;
}
