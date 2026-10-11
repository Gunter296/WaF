"use client";
import { Button, Field, Input } from "@fluentui/react-components";
import { PersonAdd20Regular } from "@fluentui/react-icons";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export function RegisterForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: form.get("name"), email: form.get("email"), password: form.get("password"), password_confirmation: form.get("password_confirmation") }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setError(body.error || "Chưa thể tạo tài khoản lúc này."); return; }
      router.replace("/dashboard");
      router.refresh();
    } catch { setError("Không kết nối được với dịch vụ tài khoản."); }
    finally { setBusy(false); }
  }
  return <form className="form-stack" onSubmit={submit}>
    <Field label="Họ và tên" required><Input name="name" autoComplete="name" minLength={2} maxLength={100} required /></Field>
    <Field label="Email" required><Input name="email" type="email" autoComplete="email" maxLength={254} required /></Field>
    <Field label="Mật khẩu" hint="Tối thiểu 10 ký tự. Tài khoản chỉ dùng trong lab." required><Input name="password" type="password" autoComplete="new-password" minLength={10} maxLength={128} required /></Field>
    <Field label="Nhập lại mật khẩu" required><Input name="password_confirmation" type="password" autoComplete="new-password" minLength={10} maxLength={128} required /></Field>
    {error && <p className="form-error" role="alert">{error}</p>}
    <Button appearance="primary" type="submit" icon={<PersonAdd20Regular />} iconPosition="after" disabled={busy}>{busy ? "Đang tạo tài khoản..." : "Tạo tài khoản demo"}</Button>
  </form>;
}
