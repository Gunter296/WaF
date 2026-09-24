"""Deterministic SYNTHETIC fixture. These values are not WAF benchmark results."""
import csv
import json
import random
from pathlib import Path


def generate(destination=None):
    destination = Path(destination or Path(__file__).parent)
    rng = random.Random(20260924)
    rows = []
    for label in (0, 1):
        for group in range(120):
            category = ["sqli", "xss", "rce"][group % 3] if label else "legitimate"
            for request in range(3):
                base = rng.choices([0, 1, 2, 3, 4, 5, 8], [45, 15, 14, 10, 8, 5, 3])[0]
                if label:
                    base = rng.choice([0, 3, 4, 5, 7, 9, 12, 15])
                scores = {name: 0 for name in ["sqli", "xss", "rce", "lfi", "rfi", "phpi", "http", "sess"]}
                if label:
                    scores[category] = rng.choice([0, 3, 5, 7, 10])
                elif group % 17 == 0:
                    scores[["sqli", "xss", "rce"][group % 3]] = rng.choice([1, 3, 5])
                high = rng.choice([0, 0, 2, 4, 6]) if label else rng.choice([0, 0, 0, 1])
                partial = (group * 3 + request) % 53 == 0
                if partial:
                    scores["xss"] = None
                rows.append({
                    "@timestamp": f"2026-01-01T00:{group % 60:02d}:{request:02d}Z",
                    "transaction": {"id": f"synthetic-{label}-{group:03d}-{request}", "request": {"uri": f"/synthetic/example/{group}", "method": "GET"}, "response": {"status": 200}, "is_interrupted": False},
                    "crs_score_summary": {"status": "partial" if partial else "complete"},
                    "crs_scores": {"inbound": {"blocking": base, "detection": base + high, "threshold": 5, "pl1": base, "pl2": 0, "pl3": high, "pl4": 0}, "category": scores},
                    "run_id": "synthetic-run-v1", "label": label,
                    "dataset_source": "synthetic-malicious" if label else "synthetic-legitimate",
                    "group_id": f"family-{label}-{group:03d}", "configuration_id": "synthetic-detectiononly",
                    "template_id": f"synthetic-template-{group}" if label else None,
                    "cve_id": None, "attack_category": category,
                    "request_error": "synthetic_timeout" if group == 4 and request == 2 else None,
                    "timeout": group == 4 and request == 2,
                })
    for index in range(4):
        row = json.loads(json.dumps(rows[index]))
        row["transaction"]["id"] = f"synthetic-unknown-{index}"
        row["group_id"] = f"unknown-{index}"
        row["label"] = "unknown"
        rows.append(row)
    rows.append(json.loads(json.dumps(rows[1])))  # intentional identical duplicate
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "synthetic.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    def flatten(node, prefix=""):
        result = {}
        for key, value in node.items():
            name = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                result.update(flatten(value, name))
            else:
                result[name] = value
        return result
    flat = [flatten(row) for row in rows]
    with (destination / "synthetic.csv").open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)
    print(f"Generated {len(rows)} SYNTHETIC documents in {destination}")


if __name__ == "__main__":
    generate()
