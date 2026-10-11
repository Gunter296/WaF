"use client";
import { Button } from "@fluentui/react-components";
import { ArrowExit20Regular } from "@fluentui/react-icons";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Brand } from "./brand";

export function AccountNav({ name, role }: { name?: string; role?: "user" | "admin" }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  async function logout() {
    setBusy(true);
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }
  return <header className="topbar"><Brand href={name ? "/dashboard" : "/"} />
    <nav className="nav-actions" aria-label="Tài khoản">
      {name ? <>{role === "admin" && <Link className="nav-link" href="/admin">Quản trị</Link>}<Link className="nav-link" href="/settings/security">Bảo mật</Link><span className="nav-user">{name}</span><Button appearance="subtle" icon={<ArrowExit20Regular />} onClick={logout} disabled={busy}>Đăng xuất</Button></> : <a className="nav-link" href="/login">Đăng nhập</a>}
    </nav>
  </header>;
}
