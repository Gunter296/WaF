"use client";
import { Button, Field, Input } from "@fluentui/react-components";
import { ArrowRight20Regular } from "@fluentui/react-icons";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setError(body.error || "Không thể đăng nhập lúc này."); return; }
      router.replace(body.role === "admin" ? "/admin" : "/dashboard");
      router.refresh();
    } catch {
      setError("Không kết nối được với dịch vụ tài khoản.");
    } finally { setBusy(false); }
  }
  return <form className="form-stack" onSubmit={submit}>
    <Field label="Email" required><Input name="email" type="email" autoComplete="username" required maxLength={254} /></Field>
    <Field label="Mật khẩu" required><Input name="password" type="password" autoComplete="current-password" required maxLength={128} /></Field>
    {error && <p className="form-error" role="alert">{error}</p>}
    <Button appearance="primary" type="submit" icon={<ArrowRight20Regular />} iconPosition="after" disabled={busy}>{busy ? "Đang xác minh..." : "Đăng nhập"}</Button>
  </form>;
}
