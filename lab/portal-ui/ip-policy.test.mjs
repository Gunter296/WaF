import assert from "node:assert/strict";
import { normalizeIPPolicy, renderIPPolicy } from "./ip-policy.mjs";

const policy = normalizeIPPolicy({ enabled: true, deny: ["172.30.0.20", "2001:db8::/32"], allow: ["172.30.0.0/24"] });
const rules = renderIPPolicy(policy);
assert.match(rules, /id:100030.*IP denylist/);
assert.match(rules, /@ipMatch 172\.30\.0\.20,2001:db8::\/32/);
assert.match(rules, /!@ipMatch 172\.30\.0\.0\/24/);
assert.match(rules, /country=%\{REQUEST_HEADERS\.X-Lab-Country\}/);
assert.ok(rules.indexOf("id:100030") < rules.indexOf("id:100031"));
assert.doesNotMatch(renderIPPolicy({ enabled: false, deny: ["172.30.0.20"], allow: [] }), /SecRule/);
assert.doesNotMatch(renderIPPolicy(policy, false), /SecRule/);
for (const invalid of ["invalid", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/24,deny"]) {
  assert.throws(() => normalizeIPPolicy({ enabled: true, deny: [invalid], allow: [] }), /invalid IP\/CIDR/);
}
console.log("IP policy rule generation passed");
