"""Request-level metrics, complete-case cohorts, and paired group uncertainty.

Positive means malicious and a positive prediction means simulated blocking.
Undefined ratios are represented by ``None`` and accompanied by a reason.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

import numpy as np
import pandas as pd


def _binary_vector(values: Iterable[Any], name: str) -> np.ndarray:
    array = np.asarray(values)
    if array.ndim != 1:
        raise ValueError(f"{name} must be a one-dimensional vector.")
    try:
        valid = np.asarray(pd.Series(array).isin([0, 1]), dtype=bool)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain only binary 0/1 values.") from exc
    if not valid.all():
        raise ValueError(f"{name} contains missing/unknown or non-binary values; filter the cohort first.")
    return array.astype(np.int8)


def require_two_classes(y: Iterable[Any], context: str = "Analysis") -> None:
    """Reject ROC/tuning cohorts with no legitimate or no malicious requests."""
    labels = _binary_vector(y, "Labels")
    n_negative = int(np.sum(labels == 0))
    n_positive = int(np.sum(labels == 1))
    if n_negative == 0 or n_positive == 0:
        raise ValueError(
            f"{context} requires both legitimate (0) and malicious (1) requests; "
            f"found {n_negative} legitimate and {n_positive} malicious. "
            "Check labels, missing-score exclusions, configuration filters, and group split; "
            "collect more independently grouped examples if necessary."
        )


def _metrics_from_counts(tp: int, fp: int, tn: int, fn: int) -> dict[str, Any]:
    tp, fp, tn, fn = int(tp), int(fp), int(tn), int(fn)
    n_positive, n_negative = tp + fn, tn + fp
    n = n_positive + n_negative
    reasons: dict[str, str] = {}

    def ratio(name: str, numerator: int, denominator: int, reason: str) -> float | None:
        if denominator == 0:
            reasons[name] = reason
            return None
        return numerator / denominator

    result = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n": n, "n_positive": n_positive, "n_negative": n_negative,
        "recall": ratio("recall", tp, n_positive, "No malicious requests (TP + FN = 0)."),
        "tpr": ratio("tpr", tp, n_positive, "No malicious requests (TP + FN = 0)."),
        "fpr": ratio("fpr", fp, n_negative, "No legitimate requests (FP + TN = 0)."),
        "precision": ratio("precision", tp, tp + fp, "No predicted blocks (TP + FP = 0)."),
        "specificity": ratio("specificity", tn, n_negative, "No legitimate requests (TN + FP = 0)."),
        "f1": ratio("f1", 2 * tp, 2 * tp + fp + fn, "No actual or predicted positives (2TP + FP + FN = 0)."),
        "prevalence": ratio("prevalence", n_positive, n, "Empty cohort (N = 0)."),
        "empirical_fpr_resolution": ratio(
            "empirical_fpr_resolution", 1, n_negative, "No legitimate requests (N_legitimate = 0)."
        ),
    }
    result["undefined_reasons"] = reasons
    return result


def confusion_metrics(y: Iterable[Any], pred: Iterable[Any]) -> dict[str, Any]:
    """Compute counts and rates without silently replacing undefined rates by zero."""
    labels = _binary_vector(y, "Labels")
    predictions = _binary_vector(pred, "Predictions")
    if labels.shape != predictions.shape:
        raise ValueError("Labels and predictions must have equal lengths.")
    return _metrics_from_counts(
        np.sum((labels == 1) & (predictions == 1)),
        np.sum((labels == 0) & (predictions == 1)),
        np.sum((labels == 0) & (predictions == 0)),
        np.sum((labels == 1) & (predictions == 0)),
    )


def common_cohort(
    df: pd.DataFrame, required_features: Iterable[str]
) -> tuple[pd.DataFrame, dict[str, Any], pd.DataFrame]:
    """Keep labeled requests with every required finite numeric score.

    A partial score summary is allowed when all requested scores are present.
    Missing scores remain missing, including in excluded records.
    """
    if "label" not in df.columns:
        raise ValueError("A normalized 'label' column is required to form an evaluation cohort.")
    features = list(dict.fromkeys(required_features))
    labels = pd.to_numeric(df["label"], errors="coerce")
    labeled = labels.isin([0, 1]).to_numpy(dtype=bool)
    reasons: list[list[str]] = [[] for _ in range(len(df))]
    for position in np.flatnonzero(~labeled):
        reasons[position].append("unknown_label")
    # Source-side request failures do not establish a request's WAF outcome.
    # Keep them in quality/audit outputs, but do not count them as bypass/block.
    source_ok = np.ones(len(df), dtype=bool)
    if "request_error" in df:
        errored = df["request_error"].map(lambda value: pd.notna(value) and str(value).strip().lower() not in {"", "null", "none", "nan"}).to_numpy(dtype=bool)
        source_ok &= ~errored
        for position in np.flatnonzero(errored):
            reasons[position].append("source_request_error")
    if "timeout" in df:
        timed_out = df["timeout"].map(lambda value: str(value).strip().lower() in {"true", "1", "1.0"}).to_numpy(dtype=bool)
        source_ok &= ~timed_out
        for position in np.flatnonzero(timed_out):
            reasons[position].append("source_timeout")
    complete = np.ones(len(df), dtype=bool)
    for feature in features:
        if feature not in df.columns:
            finite = np.zeros(len(df), dtype=bool)
        else:
            values = pd.to_numeric(df[feature], errors="coerce").to_numpy(dtype=float, na_value=np.nan)
            finite = np.isfinite(values)
        complete &= finite
        for position in np.flatnonzero(~finite):
            reasons[position].append(f"missing_or_invalid_score:{feature}")
    included = labeled & complete & source_ok
    usable = df.loc[included].copy()
    usable["label"] = labels.loc[included].astype(int)
    excluded = df.loc[~included].copy()
    excluded["exclusion_reason"] = [";".join(reasons[i]) for i in np.flatnonzero(~included)]
    by_class = {}
    for label, name in [(0, "legitimate"), (1, "malicious")]:
        class_mask = labels.eq(label).fillna(False).to_numpy(dtype=bool)
        n_total = int(class_mask.sum())
        n_included = int((class_mask & included).sum())
        by_class[name] = {
            "n_total": n_total,
            "n_included": n_included,
            "n_excluded": n_total - n_included,
            "coverage": n_included / n_total if n_total else None,
        }
    coverage = {
        "required_features": features,
        "n_total": len(df),
        "n_labeled": int(labeled.sum()),
        "n_unknown": int((~labeled).sum()),
        "n_included": int(included.sum()),
        "n_excluded": int((~included).sum()),
        "coverage": float(included.mean()) if len(df) else None,
        "labeled_coverage": float(included.sum() / labeled.sum()) if labeled.any() else None,
        "by_class": by_class,
        "excluded_reason_counts": dict(Counter(reason for row in reasons for reason in row)),
        "reason_counts_overlap": True,
    }
    return usable, coverage, excluded


def paired_group_bootstrap(
    y: Iterable[Any],
    predictions: Mapping[str, Iterable[Any]],
    groups: Iterable[Any],
    baseline_name: str,
    iterations: int,
    seed: int,
    confidence: float = 0.95,
) -> dict[str, Any]:
    """Resample whole groups, pairing each replicate across every frozen policy.

    A sampled group contributes all its rows, including repeated copies if that
    group is drawn more than once. Replicates missing either class are skipped.
    These percentile intervals quantify this empirical grouped sample only.
    """
    labels = _binary_vector(y, "Labels")
    require_two_classes(labels, "Paired group bootstrap")
    if isinstance(iterations, bool) or not isinstance(iterations, (int, np.integer)) or iterations < 0:
        raise ValueError("Bootstrap iterations must be a nonnegative integer.")
    if not 0 < confidence < 1:
        raise ValueError("Bootstrap confidence must be between 0 and 1.")
    if baseline_name not in predictions:
        raise ValueError(f"Bootstrap baseline {baseline_name!r} is absent from predictions.")
    arrays = {name: _binary_vector(pred, f"Predictions for {name}") for name, pred in predictions.items()}
    if any(array.shape != labels.shape for array in arrays.values()):
        raise ValueError("All policies must use the same cohort and order as labels.")
    group_values = np.asarray(groups)
    if group_values.ndim != 1 or len(group_values) != len(labels):
        raise ValueError("Bootstrap groups must be one-dimensional and aligned with labels.")
    if pd.isna(group_values).any() or any(isinstance(g, str) and not g.strip() for g in group_values):
        raise ValueError("Bootstrap requires a nonmissing group_id for every included request.")
    codes, unique_groups = pd.factorize(group_values, sort=False)
    members = [np.flatnonzero(codes == index) for index in range(len(unique_groups))]
    metric_names = ("tp", "fp", "tn", "fn", "recall", "tpr", "fpr", "precision", "specificity", "f1", "prevalence")
    observed = {name: confusion_metrics(labels, pred) for name, pred in arrays.items()}
    samples = {name: {metric: [] for metric in metric_names} for name in arrays}
    differences = {name: {"delta_recall": [], "delta_fpr": []} for name in arrays}
    rng = np.random.default_rng(seed)
    valid = 0
    for _ in range(iterations):
        group_draws = rng.integers(0, len(members), size=len(members))
        rows = np.concatenate([members[index] for index in group_draws])
        sample_labels = labels[rows]
        if not ((sample_labels == 0).any() and (sample_labels == 1).any()):
            continue
        valid += 1
        replicate = {name: confusion_metrics(sample_labels, pred[rows]) for name, pred in arrays.items()}
        baseline = replicate[baseline_name]
        for name, metrics in replicate.items():
            for metric in metric_names:
                if metrics[metric] is not None:
                    samples[name][metric].append(metrics[metric])
            differences[name]["delta_recall"].append(metrics["recall"] - baseline["recall"])
            differences[name]["delta_fpr"].append(metrics["fpr"] - baseline["fpr"])
    alpha = (1 - confidence) / 2

    def interval(estimate: float | int | None, values: list[float]) -> dict[str, Any]:
        if not values:
            return {"estimate": estimate, "lower": None, "upper": None, "valid_iterations": 0,
                    "reason": "No valid, defined bootstrap replicates for this metric."}
        low, high = np.quantile(values, [alpha, 1 - alpha])
        return {"estimate": estimate, "lower": float(low), "upper": float(high),
                "valid_iterations": len(values), "reason": None}

    n_legitimate = int((labels == 0).sum())
    n_legitimate_groups = int(len(np.unique(codes[labels == 0])))
    policies: dict[str, Any] = {}
    for name, metrics in observed.items():
        policies[name] = {
            "metrics": {metric: interval(metrics[metric], samples[name][metric]) for metric in metric_names},
            "delta_recall": interval(metrics["recall"] - observed[baseline_name]["recall"], differences[name]["delta_recall"]),
            "delta_fpr": interval(metrics["fpr"] - observed[baseline_name]["fpr"], differences[name]["delta_fpr"]),
            "zero_fp_limitation": (
                f"Observed FP=0 among {n_legitimate} legitimate requests in {n_legitimate_groups} groups. "
                "The ordinary bootstrap may give a degenerate FPR interval; this does not establish "
                "that population FPR or its uncertainty is zero. More independent legitimate groups are needed."
                if metrics["fp"] == 0 else None
            ),
        }
    return {
        "method": "paired group percentile bootstrap; no tuning in replicates",
        "requested_iterations": int(iterations), "valid_iterations": valid,
        "skipped_iterations": int(iterations) - valid,
        "skipped_reason": "Replicates without both legitimate and malicious requests.",
        "confidence": float(confidence), "seed": int(seed),
        "n_groups": len(members), "n_legitimate": n_legitimate,
        "n_legitimate_groups": n_legitimate_groups,
        "empirical_fpr_resolution": 1 / n_legitimate,
        "policies": policies,
    }
