"use client";
import { Button, Field, Input, Select, Option } from "@fluentui/react-components";
import { useRouter } from "next/navigation";
import { FormEvent, useRef, useState } from "react";

type Beneficiary = { id: string; display_name: string; account_number: string; bank_name: string };

export function TransferForm({ beneficiaries }: { beneficiaries: Beneficiary[] }) {
  const router = useRouter();
  const [beneficiaryId, setBeneficiaryId] = useState(beneficiaries[0]?.id || "");
  const [amount, setAmount] = useState("");
  const [purpose, setPurpose] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const idempotencyKey = useRef<string | null>(null);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setMessage("");
    try {
      idempotencyKey.current ||= crypto.randomUUID();
      const response = await fetch("/api/transfers", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ beneficiary_id: beneficiaryId, amount: Number(amount), purpose, idempotency_key: idempotencyKey.current }) });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) { setError(body.error || "Chuyển khoản chưa hoàn tất."); return; }
      setMessage(`Đã ghi nhận giao dịch giả lập. Mã ${body.transfer_id.slice(0, 8).toUpperCase()}.`);
      idempotencyKey.current = null;
      setAmount(""); setPurpose(""); router.refresh();
    } catch { setError("Không kết nối được để ghi nhận giao dịch."); }
    finally { setBusy(false); }
  }
  return <section className="transfer-panel">
    <div className="section-title"><div><h2>Chuyển khoản</h2><p>Giao dịch mô phỏng trong dữ liệu lab.</p></div></div>
    {beneficiaries.length ? <form className="form-stack" onSubmit={submit}>
      <Field label="Người thụ hưởng" required><Select value={beneficiaryId} onChange={(_, data) => setBeneficiaryId(data.value)}>{beneficiaries.map((bene) => <Option value={bene.id} text={`${bene.display_name} · ${bene.account_number}`} key={bene.id}>{bene.display_name} · {bene.account_number}</Option>)}</Select></Field>
      <Field label="Số tiền (VND)" hint="Từ 1.000 đến 10.000.000 VND" required><Input type="number" min="1000" max="10000000" step="1000" value={amount} onChange={(_, data) => setAmount(data.value)} required /></Field>
      <Field label="Nội dung" required><Input value={purpose} onChange={(_, data) => setPurpose(data.value)} maxLength={100} required /></Field>
      {error && <p className="form-error" role="alert">{error}</p>}
      {message && <p className="form-success" role="status">{message}</p>}
      <Button appearance="primary" type="submit" disabled={busy || !beneficiaryId}>{busy ? "Đang ghi nhận..." : "Xác nhận giao dịch giả lập"}</Button>
    </form> : <div className="empty-state"><strong>Chưa có người thụ hưởng</strong><span>Danh sách sẽ hiện ở đây khi có dữ liệu.</span></div>}
  </section>;
}
