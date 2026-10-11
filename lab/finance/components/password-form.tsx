"use client";
import { Button, Field, Input } from "@fluentui/react-components";
import { Password20Regular } from "@fluentui/react-icons";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export function PasswordForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    try {
      const response = await fetch("/api/auth/password", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ current_password: form.get("current_password"), new_password: form.get("new_password"), password_confirmation: form.get("password_confirmation") }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setError(body.error || "Chưa thể đổi mật khẩu lúc này."); return; }
      formElement.reset();
      setMessage("Mật khẩu đã được cập nhật. Phiên đăng nhập hiện tại đã được làm mới.");
      router.refresh();
    } catch { setError("Không kết nối được với dịch vụ tài khoản."); }
    finally { setBusy(false); }
  }
  return <form className="form-stack" onSubmit={submit}>
    <Field label="Mật khẩu hiện tại" required><Input name="current_password" type="password" autoComplete="current-password" maxLength={128} required /></Field>
    <Field label="Mật khẩu mới" hint="Tối thiểu 10 ký tự và khác mật khẩu hiện tại." required><Input name="new_password" type="password" autoComplete="new-password" minLength={10} maxLength={128} required /></Field>
    <Field label="Nhập lại mật khẩu mới" required><Input name="password_confirmation" type="password" autoComplete="new-password" minLength={10} maxLength={128} required /></Field>
    {error && <p className="form-error" role="alert">{error}</p>}
    {message && <p className="form-success" role="status">{message}</p>}
    <Button appearance="primary" type="submit" icon={<Password20Regular />} iconPosition="after" disabled={busy}>{busy ? "Đang cập nhật..." : "Cập nhật mật khẩu"}</Button>
  </form>;
}
