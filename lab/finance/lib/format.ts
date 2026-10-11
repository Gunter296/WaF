export type Transaction = {
  id: string;
  kind: string;
  merchant: string;
  description: string;
  amount: string;
  created_at: string;
  reference: string;
};

export function money(amount: string | number, currency = "VND") {
  return new Intl.NumberFormat("vi-VN", { style: "currency", currency, maximumFractionDigits: 0 }).format(Number(amount));
}

export function dateTime(value: string | Date) {
  return new Intl.DateTimeFormat("vi-VN", { dateStyle: "medium", timeStyle: "short", timeZone: "Asia/Ho_Chi_Minh" }).format(new Date(value));
}
