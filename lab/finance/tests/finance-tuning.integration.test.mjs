import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const stage = process.env.FINANCE_WAF_STAGE;
test(`edge and Coraza ${stage || "stage not selected"} traffic`, { skip: !["before", "after", "revoked"].includes(stage) }, () => {
  const result = spawnSync(process.execPath, ["scripts/finance-tuning.mjs", stage], { encoding: "utf8", env: process.env, timeout: 70_000 });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /request_id/);
});
