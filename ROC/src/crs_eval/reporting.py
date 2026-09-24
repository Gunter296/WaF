"""Offline HTML, labeled figures, and explicit limitations."""
from __future__ import annotations

import base64
import html
import os
from pathlib import Path

import pandas as pd

from .utils import read_json


def _pyplot(output):
    os.environ.setdefault("MPLCONFIGDIR", str(Path(output) / ".matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib import pyplot as plt
    return plt


def plot_scores(curves, output, low_fpr=0.05):
    plt = _pyplot(output)
    for filename, kind, low in [("roc_curves.png", "roc", False), ("roc_low_fpr.png", "roc", True), ("precision_recall_curves.png", "pr", False)]:
        fig, ax = plt.subplots(figsize=(9, 6), layout="constrained")
        for feature, curve in curves.items():
            x, y = (curve["fpr"], curve["tpr"]) if kind == "roc" else (curve["recall"], curve["precision"])
            # ROC points are connected linearly: steps-post would misrepresent
            # AUC when a tied threshold moves FPR and TPR simultaneously.
            ax.plot(x, y, label=f"{feature} (N={curve['n']})")
        ax.set(xlabel="False positive rate" if kind == "roc" else "Recall", ylabel="True positive rate (Recall)" if kind == "roc" else "Precision", title=f"Development — {'ROC' if kind == 'roc' else 'Precision–Recall'}{' / low FPR' if low else ''}\nPer-score available cohorts; denominators may differ", xlim=(0, low_fpr if low else 1), ylim=(0, 1.02))
        ax.grid(alpha=0.2)
        if curves:
            ax.legend(fontsize=8, loc="best")
        fig.savefig(Path(output) / filename, dpi=150)
        plt.close(fig)


def plot_tradeoffs(candidates, output):
    plt = _pyplot(output)
    fig, ax = plt.subplots(figsize=(9, 6), layout="constrained")
    for family, group in candidates.groupby("family", sort=False):
        ax.scatter(group["fpr"], group["tpr"], s=15, alpha=0.45, label=family)
    frontier = candidates[candidates["pareto"]].drop_duplicates(["fpr", "tpr"]).sort_values("fpr")
    ax.scatter(frontier["fpr"], frontier["tpr"], marker="x", s=70, color="black", label="Non-dominated Pareto points")
    ax.set(xlabel="False positive rate", ylabel="True positive rate (Recall)", title=f"Development policy trade-offs — common cohort N={int(candidates.iloc[0]['n'])}\n{len(candidates)} evaluated policies; each point is a hard decision", xlim=(-0.02, 1.02), ylim=(-0.02, 1.02))
    ax.legend(fontsize=7, loc="best")
    ax.grid(alpha=0.2)
    fig.savefig(Path(output) / "policy_tradeoffs.png", dpi=150)
    plt.close(fig)


def render_report(output, manifest, quality, locked, metrics, uncertainty, grouped):
    output = Path(output)
    synthetic = manifest.get("synthetic", False)
    def table(frame):
        return frame.to_html(index=False, escape=True, na_rep="null", float_format=lambda x: f"{x:.5g}") if len(frame) else "<p>No records.</p>"
    def detail(value):
        import json
        return "<pre>" + html.escape(json.dumps(value, ensure_ascii=False, indent=2)) + "</pre>"
    images = []
    for name in ("roc_curves.png", "roc_low_fpr.png", "precision_recall_curves.png", "policy_tradeoffs.png"):
        path = output / name
        if path.exists():
            images.append(f'<figure><img alt="{html.escape(name)}" src="data:image/png;base64,{base64.b64encode(path.read_bytes()).decode()}"><figcaption>{name}</figcaption></figure>')
    headline = "SYNTHETIC DEMONSTRATION — NOT A REAL WAF BENCHMARK" if synthetic else "Offline dataset evaluation — scope limited to the supplied data"
    columns = [c for c in ["policy", "development_fpr_target", "n", "n_positive", "n_negative", "recall", "fpr", "precision", "fp", "fn", "delta_recall_vs_baseline", "delta_fpr_vs_baseline", "test_fpr_target_violated"] if c in metrics]
    warnings = list(quality.get("warnings", [])) + manifest.get("warnings", [])
    limitations = [
        "Positive = verified malicious; predicted positive = proposed block. Unknown labels are excluded from supervised evaluation.",
        "Source request errors and timeouts are retained in quality reporting but excluded from supervised ROC, tuning and test metrics, with explicit coverage reasons.",
        "Baseline is crs_anomaly_baseline_simulated: inbound_blocking >= configured per-request threshold, or an explicitly supplied fixed threshold. Direct blocking rules, parsing/body limits and engine interruption timing are not fully simulated.",
        "DetectionOnly score decisions simulate policy. HTTP 403 and actual interruption are not ground truth. Backend HTTP 200 does not establish exploit success.",
        "Development determines features, candidate thresholds and policies. Test evaluates the locked policies without retuning, including when its FPR exceeds the target.",
        "All compared policies use the identical complete-case cohort. Individual score ROC/PR plots use per-score available development rows; their sample sizes can differ and are not a common-cohort ranking.",
        "Average Precision is sklearn average_precision_score, not trapezoidal PR area. Unordered hard-policy trade-off points have no ROC-AUC.",
        "Bootstrap resamples entire groups with replacement, paired across every policy and the baseline; policies remain fixed. Replicates without both classes are skipped. It estimates test sampling uncertainty conditional on the selected policies, not selection uncertainty.",
        "Zero observed false positives can produce a degenerate bootstrap FPR interval. This does not establish zero population FPR or zero uncertainty. Inspect legitimate request/group counts and empirical FPR resolution (1 / N legitimate).",
        "Precision depends on the malicious prevalence in this dataset and must not be extrapolated directly to production.",
        "Request-level results cannot be combined with CVE/template-level counts. SQLi-specific analysis needs independently sourced attack labels; other malicious categories are never treated as legitimate.",
        "No WAF configuration, Elasticsearch index, network scanner, or live replay was changed or executed by this tool.",
    ]
    if synthetic:
        limitations.insert(0, "All input data and displayed measurements in this report are synthetic fixtures. No real benchmark has been performed.")
    ci_rows = []
    for policy, result in uncertainty.get("policies", {}).items():
        for metric, interval in result.get("metrics", {}).items():
            ci_rows.append({"policy": policy, "metric": metric, **interval})
        for metric in ("delta_recall", "delta_fpr"):
            if metric in result:
                ci_rows.append({"policy": policy, "metric": metric, **result[metric]})
    body = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CRS threshold evaluation</title>
<style>body{{font:15px/1.55 system-ui,sans-serif;color:#17283b;background:#f5f7fb;margin:0}}main{{max-width:1280px;margin:auto;padding:36px}}h1,h2{{color:#122d4b}}.notice{{padding:16px;border-left:5px solid #d47b00;background:#fff0d9;font-weight:bold}}section{{background:white;padding:24px;margin:24px 0;border-radius:10px;overflow:auto}}table{{border-collapse:collapse;font-size:12px;white-space:nowrap}}th,td{{padding:8px;border:1px solid #dde3eb;text-align:right}}th{{background:#eaf0f7}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}img{{width:100%;max-width:1000px}}figure{{margin:24px 0}}li{{margin-bottom:8px}}</style>
<main><h1>Coraza + CRS threshold evaluation</h1><p class="notice">{headline}</p>
<p>Request-level decisions · group-separated development/test · locked policy evaluation</p>
<section><h2>Test comparison</h2>{table(metrics[columns])}<p>All rows above use the same test cohort. Null values have explicit reasons in test_metrics.csv. Targets are development constraints, not test guarantees.</p></section>
<section><h2>Coverage and split</h2>{detail(manifest.get('split', {}))}{detail(manifest.get('test_coverage', {}))}<h3>Development comparison cohort</h3>{detail(locked.get('development_coverage', {}))}</section>
<section><h2>Data quality and exclusions</h2>{detail(quality)}<h3>Warnings</h3>{detail(warnings)}</section>
<section><h2>Method and locked search</h2>{detail(locked.get('search', {}))}<h3>Development-only feature exclusions</h3>{detail(locked.get('excluded_features', {}))}<h3>Policy definitions</h3>{detail(locked.get('policies', []))}</section>
<section><h2>Paired group bootstrap uncertainty</h2><p>Requested {uncertainty.get('requested_iterations')}; valid {uncertainty.get('valid_iterations')}; groups {uncertainty.get('n_groups')}; legitimate requests {uncertainty.get('n_legitimate')}. Confidence {uncertainty.get('confidence')}.</p>{table(pd.DataFrame(ci_rows))}{detail({k:v for k,v in uncertainty.items() if k != 'policies'})}</section>
<section><h2>Dataset, attack category and threshold strata</h2>{table(grouped)}<p>Attack category versus legitimate rows include all legitimate requests plus only the named malicious category. Source-only and category-only strata with one class have null FPR/Recall as appropriate.</p></section>
<section><h2>Development figures</h2>{''.join(images)}</section>
<section><h2>Assumptions and limitations</h2><ul>{''.join('<li>'+html.escape(v)+'</li>' for v in limitations)}</ul></section>
<section><h2>Reproducibility manifest</h2>{detail(manifest)}</section></main></html>"""
    (output / "report.html").write_text(body, encoding="utf-8")
