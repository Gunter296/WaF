import test from "node:test";
import assert from "node:assert/strict";
import { parseReconcileFilter } from "../lib/reconcile-filter.mjs";

test("parses a legitimate merchant name with an apostrophe and bounded amounts/dates", () => {
  assert.deepEqual(parseReconcileFilter("merchant contains 'O''Connor Market' AND amount between 50000 and 250000 AND date between 2026-10-01 and 2026-10-31"), {
    merchant: "O'Connor Market", minAmount: 50000, maxAmount: 250000, from: "2026-10-01", to: "2026-10-31",
  });
});

test("allows double-quoted text containing an apostrophe", () => {
  assert.equal(parseReconcileFilter('merchant contains "O\'Connor Market" AND amount between 50000 and 250000 AND date between 2026-10-01 and 2026-10-31').merchant, "O'Connor Market");
});

test("rejects extra operators and SQL-shaped input instead of passing it to a query", () => {
  assert.throws(() => parseReconcileFilter("merchant contains 'x' OR 1=1--' AND amount between 0 and 9 AND date between 2026-10-01 and 2026-10-31"));
  assert.throws(() => parseReconcileFilter("merchant contains 'x' AND amount between 9 and 0 AND date between 2026-10-01 and 2026-10-31"));
  assert.throws(() => parseReconcileFilter("merchant contains 'x' AND amount between 0 and 9 AND date between 2026-02-30 and 2026-10-31"));
  assert.throws(() => parseReconcileFilter("merchant contains 'x' AND amount between 0 and 9 AND date between 2026-10-31 and 2026-10-01"));
});
