const MAX_LENGTH = 240;

function tokenize(source) {
  const tokens = [];
  for (let i = 0; i < source.length;) {
    if (/\s/.test(source[i])) { i++; continue; }
    if (source[i] === "'" || source[i] === '"') {
      const quote = source[i];
      i++;
      let value = "";
      let closed = false;
      while (i < source.length) {
        if (source[i] === quote && source[i + 1] === quote) { value += quote; i += 2; continue; }
        if (source[i] === quote) { i++; closed = true; break; }
        value += source[i++];
      }
      if (!closed) throw new Error("Tên thương nhân cần đóng dấu nháy đơn.");
      tokens.push({ type: "string", value });
      continue;
    }
    const date = source.slice(i).match(/^\d{4}-\d{2}-\d{2}/);
    if (date) { tokens.push({ type: "date", value: date[0] }); i += date[0].length; continue; }
    const number = source.slice(i).match(/^\d{1,12}/);
    if (number) { tokens.push({ type: "number", value: number[0] }); i += number[0].length; continue; }
    const word = source.slice(i).match(/^[A-Za-z_]+/);
    if (word) { tokens.push({ type: "word", value: word[0].toLowerCase() }); i += word[0].length; continue; }
    throw new Error("Biểu thức chứa ký tự hoặc cú pháp không được hỗ trợ.");
  }
  return tokens;
}

export function parseReconcileFilter(source) {
  if (typeof source !== "string" || source.length < 10 || source.length > MAX_LENGTH) {
    throw new Error(`Biểu thức cần dài từ 10 đến ${MAX_LENGTH} ký tự.`);
  }
  const tokens = tokenize(source);
  let i = 0;
  const take = (type, expected) => {
    const token = tokens[i++];
    if (!token || token.type !== type || (expected && token.value !== expected)) {
      throw new Error(`Cú pháp không hợp lệ tại phần ${expected || type}.`);
    }
    return token.value;
  };
  take("word", "merchant"); take("word", "contains");
  const merchant = take("string");
  take("word", "and"); take("word", "amount"); take("word", "between");
  const minAmount = Number(take("number")); take("word", "and"); const maxAmount = Number(take("number"));
  take("word", "and"); take("word", "date"); take("word", "between");
  const from = take("date"); take("word", "and"); const to = take("date");
  if (i !== tokens.length) throw new Error("Có nội dung thừa sau biểu thức lọc.");
  if (merchant.length < 2 || merchant.length > 80 || /[\u0000-\u001f]/.test(merchant)) throw new Error("Tên thương nhân cần dài từ 2 đến 80 ký tự.");
  if (!Number.isSafeInteger(minAmount) || !Number.isSafeInteger(maxAmount) || minAmount < 0 || maxAmount < minAmount) throw new Error("Khoảng tiền không hợp lệ.");
  const validDay = (day) => {
    const parsed = new Date(`${day}T00:00:00.000Z`);
    return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === day;
  };
  if (!validDay(from) || !validDay(to) || from > to) throw new Error("Khoảng ngày không hợp lệ.");
  return { merchant, minAmount, maxAmount, from, to };
}
