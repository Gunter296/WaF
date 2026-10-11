import test from "node:test";
import assert from "node:assert/strict";
import { createSeedTransactions } from "../lib/seed-fixtures.mjs";

test("seed supplies 60 stable, varied transaction fixtures", () => {
  const first = createSeedTransactions();
  const second = createSeedTransactions();
  assert.equal(first.length, 60);
  assert.deepEqual(first, second);
  assert.equal(new Set(first.map((item) => item.id)).size, 60);
  assert.equal(new Set(first.map((item) => item.accountId)).size, 3);
  assert.ok(new Set(first.map((item) => item.merchant)).size >= 10);
  assert.ok(first.some((item) => item.amount > 0));
  assert.ok(first.some((item) => item.amount < 0));
  assert.ok(first.some((item) => item.merchant === "O'Connor Market"));
});
