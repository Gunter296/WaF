const accounts = [
  { id: "acct-an-2048", code: "AN", merchants: ["O'Connor Market", "Cà phê Sông Xanh", "Nhà sách Bến Thành", "Điện lực miền Nam", "Mây Home", "Cấp nước thành phố"] },
  { id: "acct-linh-3106", code: "LINH", merchants: ["Mộc Design Studio", "Chợ Bến Thành", "Nhà sách Bến Thành", "Bếp Nhà Mình", "Metro số 1", "Điện lực miền Nam"] },
  { id: "acct-quang-5821", code: "QUANG", merchants: ["Đại học Nam Sài Gòn", "Hải sản Cầu Mống", "Hiệu thuốc An Khang", "Cà phê Sông Xanh", "Cấp nước thành phố", "Nhà sách Bến Thành"] },
];
const kinds = ["purchase", "bill", "purchase", "refund", "purchase", "salary", "purchase", "bill", "purchase", "refund"];
const descriptions = [
  "Thanh toán tại cửa hàng", "Thanh toán hóa đơn hàng tháng", "Mua sắm trong ngày", "Hoàn tiền đơn hàng",
  "Chi tiêu sinh hoạt", "Thu nhập tháng", "Thanh toán dịch vụ", "Hóa đơn định kỳ", "Mua thực phẩm", "Điều chỉnh giao dịch",
];
const baseAmounts = [84500, 186000, 245000, 128000, 394000, 14800000, 742500, 166000, 315000, 215000];

export function createSeedTransactions() {
  return accounts.flatMap(({ id, code, merchants }) => Array.from({ length: 20 }, (_, index) => {
    const sequence = index + 1;
    const kind = kinds[index % kinds.length];
    const magnitude = baseAmounts[index % baseAmounts.length] + ((index * 7919) % 87000);
    const amount = ["salary", "refund"].includes(kind) ? magnitude : -magnitude;
    const timestamp = new Date(Date.UTC(2026, 4, 5 + index * 8, (index * 7) % 24, (index * 13) % 60));
    return {
      id: `tx-seed-${code.toLowerCase()}-${String(sequence).padStart(2, "0")}`,
      accountId: id,
      kind,
      merchant: merchants[(index * 5 + (code.length % merchants.length)) % merchants.length],
      description: descriptions[index % descriptions.length],
      amount,
      createdAt: timestamp.toISOString(),
      reference: `REF-SEED-${code}-${String(sequence).padStart(2, "0")}`,
    };
  }));
}
