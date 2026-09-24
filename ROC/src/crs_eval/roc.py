"""Development-only continuous-score ROC/PR and complete threshold tables."""

from __future__ import annotations

import json
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

from .metrics import _metrics_from_counts, common_cohort, require_two_classes


TIE_BREAK = "maximum recall, then minimum FPR, then highest threshold (none > numeric > all)"


def _threshold_order(row: dict[str, Any]) -> tuple[int, float]:
    kind = row["threshold_kind"]
    return ({"none": 0, "numeric": 1, "all": 2}[kind], -row["threshold"] if kind == "numeric" else 0.0)


def analyze_scores(
    development: pd.DataFrame, features: Iterable[str], fpr_targets: Iterable[float]
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Analyze each score on its own available development cohort.

    Threshold candidates use ``>=`` and every distinct development score plus
    explicit ``all``/``none`` sentinels. No test data is accepted by this API.
    Cohorts may differ across features, so these results are not a fair policy
    ranking. Direct policy comparisons must instead use a shared cohort.
    """
    targets = list(dict.fromkeys(float(target) for target in fpr_targets))
    if any(not np.isfinite(target) or target < 0 or target > 1 for target in targets):
        raise ValueError("Each FPR target must be a finite number between 0 and 1.")
    labeled, _, _ = common_cohort(development, [])
    require_two_classes(labeled["label"], "Development score analysis")
    score_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    curves: dict[str, Any] = {}
    for feature in dict.fromkeys(features):
        cohort, coverage, _ = common_cohort(development, [feature])
        y = cohort["label"].to_numpy(dtype=int)
        positive = int((y == 1).sum())
        negative = int((y == 0).sum())
        cohort_name = f"feature_available:{feature}"
        info: dict[str, Any] = {
            "feature": feature, "split": "development", "cohort": cohort_name,
            "n": len(y), "n_positive": positive, "n_negative": negative,
            "n_source": len(development), "coverage": coverage["coverage"],
            "legitimate_coverage": coverage["by_class"]["legitimate"]["coverage"],
            "malicious_coverage": coverage["by_class"]["malicious"]["coverage"],
            "cohort_note": "Own available-score cohort; denominators can differ between features.",
            "roc_auc": None, "average_precision": None,
            "ap_method": "sklearn.metrics.average_precision_score (non-interpolated)",
            "prevalence": positive / len(y) if len(y) else None,
            "empirical_fpr_resolution": 1 / negative if negative else None,
            "tie_break": TIE_BREAK,
        }
        if not len(y):
            info.update(status="excluded", reason="Score is entirely missing/invalid in labeled development requests.")
            score_rows.append(info)
            continue
        if not positive or not negative:
            info.update(status="excluded", reason="Available-score cohort lacks legitimate or malicious requests; ROC/PR skipped.")
            score_rows.append(info)
            continue
        scores = pd.to_numeric(cohort[feature]).to_numpy(dtype=float)
        unique = np.unique(scores)
        constant = len(unique) == 1
        info.update(
            status="constant" if constant else "ok",
            reason="Constant score: no ranking discrimination." if constant else None,
            n_unique=len(unique), roc_auc=float(roc_auc_score(y, scores)),
            average_precision=float(average_precision_score(y, scores)),
        )
        fpr, tpr, raw_thresholds = roc_curve(y, scores, drop_intermediate=False)
        precision, recall, pr_thresholds = precision_recall_curve(y, scores)
        curves[feature] = {
            "feature": feature, "split": "development", "cohort": cohort_name,
            "n": len(y), "n_positive": positive, "n_negative": negative,
            "coverage": coverage, "constant": constant,
            "roc_auc": info["roc_auc"], "average_precision": info["average_precision"],
            "fpr": fpr.tolist(), "tpr": tpr.tolist(),
            "precision": precision.tolist(), "recall": recall.tolist(),
            "roc_thresholds": [
                {"threshold_kind": "none", "threshold": None} if index == 0
                else {"threshold_kind": "numeric", "threshold": float(threshold)}
                for index, threshold in enumerate(raw_thresholds)
            ],
            "pr_thresholds": pr_thresholds.tolist(),
        }
        pos_scores = np.sort(scores[y == 1])
        neg_scores = np.sort(scores[y == 0])
        thresholds = [("none", None)] + [("numeric", float(value)) for value in unique[::-1]] + [("all", None)]
        feature_rows = []
        for kind, threshold in thresholds:
            if kind == "none":
                tp = fp = 0
            elif kind == "all":
                tp, fp = positive, negative
            else:
                tp = positive - int(np.searchsorted(pos_scores, threshold, side="left"))
                fp = negative - int(np.searchsorted(neg_scores, threshold, side="left"))
            metrics = _metrics_from_counts(tp, fp, negative - fp, positive - tp)
            metrics["undefined_reasons"] = json.dumps(metrics["undefined_reasons"], sort_keys=True)
            feature_rows.append({
                "feature": feature, "split": "development", "cohort": cohort_name,
                "threshold_kind": kind, "threshold": threshold, "operator": ">=",
                "coverage": coverage["coverage"],
                "legitimate_coverage": info["legitimate_coverage"],
                "malicious_coverage": info["malicious_coverage"],
                **metrics, "selected_for_targets": [], "none_only_for_targets": [],
            })
        selected_summary = []
        for target in targets:
            feasible = [row for row in feature_rows if row["fpr"] <= target]
            best = min(feasible, key=lambda row: (-row["recall"], row["fpr"], _threshold_order(row)))
            only_none = not any(row["tp"] + row["fp"] > 0 for row in feasible)
            best["selected_for_targets"].append(target)
            if only_none:
                best["none_only_for_targets"].append(target)
            selected_summary.append({
                "fpr_target": target, "threshold_kind": best["threshold_kind"],
                "threshold": best["threshold"], "recall": best["recall"], "fpr": best["fpr"],
                "only_feasible_by_blocking_none": only_none,
                "target_below_empirical_fpr_resolution": target < 1 / negative,
            })
        info["selected_thresholds"] = json.dumps(selected_summary, sort_keys=True, allow_nan=False)
        for row in feature_rows:
            row["selected_for_targets"] = json.dumps(row["selected_for_targets"])
            row["none_only_for_targets"] = json.dumps(row["none_only_for_targets"])
        score_rows.append(info)
        candidate_rows.extend(feature_rows)
    metrics_frame = pd.DataFrame(score_rows)
    candidates_frame = pd.DataFrame(candidate_rows)
    # Keep sentinels as real Python None even in DataFrame.to_dict() consumers.
    if "threshold" in candidates_frame:
        candidates_frame["threshold"] = candidates_frame["threshold"].astype(object).where(candidates_frame["threshold"].notna(), None)
    return metrics_frame, candidates_frame, curves
