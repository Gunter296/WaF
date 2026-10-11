"use client";
import { Button, Field, Input, Option, Select } from "@fluentui/react-components";
import { ArrowDownLeft20Regular, ArrowUpRight20Regular, DocumentText20Regular, Search20Regular } from "@fluentui/react-icons";
import { FormEvent, useState } from "react";
import { dateTime, money, Transaction } from "../lib/format";

type PageData = { items: Transaction[]; page: number; limit: number; total: number };
type ReconcileResult = { items: Transaction[] };

function rowsMarkup(items: Transaction[], empty: string) {
  if (!items.length) return <div className="empty-state"><strong>Chưa có giao dịch phù hợp</strong><span>{empty}</span></div>;
  return <div className="transaction-list">{items.map((item) => <article className="transaction-row" key={item.id}>
    <span className={`transaction-mark ${Number(item.amount) > 0 ? "positive" : "negative"}`}>{Number(item.amount) > 0 ? <ArrowDownLeft20Regular /> : <ArrowUpRight20Regular />}</span>
    <div className="transaction-copy"><a href={`/transactions/${encodeURIComponent(item.id)}`}><strong>{item.merchant}</strong></a><span>{item.description}</span><time dateTime={item.created_at}>{dateTime(item.created_at)}</time></div>
    <strong className={`transaction-amount ${Number(item.amount) > 0 ? "positive-text" : ""}`}>{Number(item.amount) > 0 ? "+" : "−"}{money(Math.abs(Number(item.amount)))}</strong>
    <a className="icon-link" href={`/api/documents/${encodeURIComponent(item.id)}`} target="_blank" aria-label={`Mở chứng từ ${item.reference}`}><DocumentText20Regular /></a>
  </article>)}</div>;
}

export function TransactionBrowser({ initial }: { initial: PageData }) {
  const [data, setData] = useState(initial);
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function search(page = 1) {
    setBusy(true); setError("");
    try {
      const params = new URLSearchParams({ page: String(page), query, kind, from, to });
      const response = await fetch(`/api/transactions?${params}`, { cache: "no-store" });
      const body = await response.json().catch(() => ({}));
      if (response.ok) setData(body); else setError(body.error || "Không tải được giao dịch.");
    } catch { setError("Không kết nối được để tải giao dịch."); }
    finally { setBusy(false); }
  }
  return <section className="content-section" aria-labelledby="transactions-heading">
    <div className="section-title"><div><h2 id="transactions-heading">Giao dịch</h2><p>Hoạt động gần đây trên tài khoản của bạn</p></div><span className="subtle-count">{data.total} giao dịch</span></div>
    <form className="search-row" onSubmit={(event: FormEvent) => { event.preventDefault(); void search(1); }}>
      <Field label="Tìm theo thương nhân, nội dung hoặc mã tham chiếu"><Input value={query} onChange={(_, data) => setQuery(data.value)} placeholder="Ví dụ: O'Connor Market" contentBefore={<Search20Regular />} /></Field>
      <Field label="Loại giao dịch"><Select value={kind} onChange={(_, data) => setKind(data.value)}><Option value="">Tất cả</Option><Option value="salary">Thu nhập</Option><Option value="purchase">Mua sắm</Option><Option value="refund">Hoàn tiền</Option><Option value="bill">Hóa đơn</Option><Option value="transfer_in">Tiền nhận</Option><Option value="transfer_out">Chuyển đi</Option></Select></Field>
      <Field label="Từ ngày"><Input type="date" value={from} onChange={(_, data) => setFrom(data.value)} /></Field>
      <Field label="Đến ngày"><Input type="date" value={to} onChange={(_, data) => setTo(data.value)} /></Field>
      <Button appearance="secondary" type="submit" disabled={busy}>{busy ? "Đang tìm..." : "Lọc giao dịch"}</Button>
    </form>
    {error && <p className="form-error" role="alert">{error}</p>}
    {rowsMarkup(data.items, "Thử đổi từ khóa tìm kiếm hoặc bộ lọc.")}
    <div className="pagination"><span>Trang {data.page} / {Math.max(1, Math.ceil(data.total / data.limit))}</span><div>
      <Button appearance="subtle" disabled={busy || data.page <= 1} onClick={() => void search(data.page - 1)}>Trước</Button>
      <Button appearance="subtle" disabled={busy || data.page * data.limit >= data.total} onClick={() => void search(data.page + 1)}>Tiếp</Button>
    </div></div>
  </section>;
}

export function ReconcileSearch() {
  const [expression, setExpression] = useState("");
  const [items, setItems] = useState<Transaction[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function loadExample() {
    setError("");
    try {
      const response = await fetch("/api/transactions/reconcile/example", { cache: "no-store" });
      const body = await response.json();
      if (response.ok) setExpression(body.expression);
      else setError(body.error || "Không tải được ví dụ lọc.");
    } catch { setError("Không kết nối được để tải ví dụ lọc."); }
  }
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setItems(null);
    try {
      const response = await fetch("/api/transactions/reconcile/search", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ expression }) });
      const body = await response.json().catch(() => ({}));
      if (response.ok) setItems(body.items); else setError(body.error || "Không thể đối soát.");
    } catch { setError("Không kết nối được để đối soát giao dịch."); }
    finally { setBusy(false); }
  }
  return <section className="reconcile-section" aria-labelledby="reconcile-heading">
    <div className="section-title"><div><h2 id="reconcile-heading">Đối soát giao dịch</h2><p>Kết hợp thương nhân, khoảng tiền và ngày ghi nhận.</p></div></div>
    <form className="form-stack" onSubmit={submit}>
      <Field label="Biểu thức lọc" hint="Cú pháp: merchant contains 'tên' AND amount between số và số AND date between YYYY-MM-DD and YYYY-MM-DD" required>
        <Input value={expression} onChange={(_, data) => setExpression(data.value)} required maxLength={240} aria-describedby="expression-hint" />
      </Field>
      <span className="helper" id="expression-hint">Tên có dấu nháy đơn dùng hai dấu liên tiếp, ví dụ O''Connor.</span>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="form-actions"><Button appearance="secondary" type="button" onClick={() => void loadExample()}>Điền ví dụ giao dịch</Button><Button appearance="primary" type="submit" disabled={busy}>{busy ? "Đang đối soát..." : "Tìm giao dịch"}</Button></div>
    </form>
    {items && <div className="reconcile-results"><div className="section-title compact"><strong>{items.length} kết quả</strong></div>{rowsMarkup(items, "Không có kết quả cho biểu thức này.")}</div>}
  </section>;
}
