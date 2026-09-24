"""Reproducible group splitting that never inspects score values."""
from __future__ import annotations

import hashlib
import json
from typing import Any

import numpy as np
import pandas as pd

from .validation import DataValidationError
from .utils import fingerprint_dataframe


def split_fingerprint(manifest: pd.DataFrame) -> str:
    ordered = manifest.sort_values(["run_id", "request_id"], kind="stable")
    records = ordered.astype(object).where(ordered.notna(), None).to_dict("records")
    return hashlib.sha256(json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def split_data(frame: pd.DataFrame, config: dict[str, Any]) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """Split whole groups, preserving unknown-label requests as ``excluded``.

    A deterministic bounded search uses only labels and group sizes, never scores,
    to select a feasible split near the requested request-level class proportions.
    """
    data_fingerprint = fingerprint_dataframe(frame)
    frame = frame.copy()
    specification = config.get("split", {})
    fraction = float(specification.get("test_size", 0.3))
    seed = int(specification.get("seed", 42))
    if not 0 < fraction < 1:
        raise DataValidationError("split.test_size must be strictly between 0 and 1.")
    group_column = config.get("grouping", {}).get("field", "group_id")
    if group_column != "group_id" and group_column in frame:
        frame["group_id"] = frame[group_column]
    missing = frame.group_id.isna() | frame.group_id.astype(str).str.strip().eq("")
    warnings: list[str] = []
    if missing.any():
        if not config.get("grouping", {}).get("allow_request_fallback", False):
            raise DataValidationError("Missing group_id; supply meaningful request-family groups or explicitly enable grouping.allow_request_fallback.")
        fallback = frame.loc[missing, ["run_id", "request_id"]].astype(str).apply(lambda row: "__request_fallback__" + json.dumps(row.tolist(), separators=(",", ":")), axis=1)
        if set(fallback) & set(frame.loc[~missing, "group_id"].astype(str)):
            raise DataValidationError("Generated fallback group IDs collide with supplied group IDs; provide explicit groups.")
        frame.loc[missing, "group_id"] = fallback
        warnings.append(f"Explicit request-level fallback used for {int(missing.sum())} requests; near-duplicate leakage cannot be ruled out.")
    frame["group_id"] = frame.group_id.astype(str)
    eligible = frame.loc[frame.label.isin([0, 1])]
    if eligible.label.nunique() != 2:
        raise DataValidationError("Group splitting requires both legitimate and malicious labels.")
    counts = pd.crosstab(eligible.group_id, eligible.label).reindex(columns=[0, 1], fill_value=0).sort_index()
    for label in [0, 1]:
        if int(counts[label].gt(0).sum()) < 2:
            raise DataValidationError(f"Label {label} occurs in fewer than two groups. Collect more independent groups or repair grouping; both splits require both labels.")
    groups = counts.index.to_numpy()
    label_counts = counts.to_numpy(dtype=int)
    totals = label_counts.sum(axis=0)
    group_count = len(groups)
    rng = np.random.default_rng(seed)
    # Exhaustive feasibility for small datasets; use reproducible permutations for larger ones.
    def candidates():
        if group_count <= 16:
            for mask in rng.permutation(np.arange(1, (1 << group_count) - 1)):
                yield np.array([i for i in range(group_count) if mask & (1 << i)], dtype=int)
        else:
            target_groups = max(1, min(group_count - 1, round(group_count * fraction)))
            for _ in range(min(4096, max(512, 16 * group_count))):
                permutation = rng.permutation(group_count)
                for size in sorted({max(1, target_groups - 1), target_groups, min(group_count - 1, target_groups + 1)}):
                    yield permutation[:size]
    best: np.ndarray | None = None
    best_error: tuple[float, float] | None = None
    for indices in candidates():
        test_counts = label_counts[indices].sum(axis=0)
        if np.any(test_counts == 0) or np.any(test_counts == totals):
            continue
        deviation = (float(np.abs(test_counts / totals - fraction).sum()), abs(len(indices) / group_count - fraction))
        if best_error is None or deviation < best_error:
            best, best_error = indices, deviation
    if best is None:
        raise DataValidationError("Cannot find a group-disjoint split containing both labels. Add independent groups, adjust test_size, or repair group assignments.")
    test_groups = set(groups[best])
    frame["split"] = "excluded"
    known = frame.label.isin([0, 1])
    frame.loc[known, "split"] = np.where(frame.loc[known, "group_id"].isin(test_groups), "test", "development")
    manifest = frame[["run_id", "request_id", "group_id", "label", "split"]].copy()
    manifest["exclusion_reason"] = np.where(manifest.split.eq("excluded"), "unknown_label", "")
    development_groups = set(frame.loc[frame.split.eq("development"), "group_id"])
    actual_test_groups = set(frame.loc[frame.split.eq("test"), "group_id"])
    if development_groups & actual_test_groups:
        raise AssertionError("Internal error: group overlap detected.")
    fingerprint = split_fingerprint(manifest)
    metadata = {
        "seed": seed, "requested_test_size": fraction, "fingerprint": fingerprint, "split_fingerprint": fingerprint,
        "data_fingerprint": data_fingerprint,
        "method": "deterministic_group_split_class_balance", "uses_scores": False,
        "group_overlap": [], "warnings": warnings,
        "group_counts": {name: int(frame.loc[frame.split.eq(name), "group_id"].nunique()) for name in ["development", "test", "excluded"]},
        "class_counts": {name: {"legitimate": int(((frame.split == name) & (frame.label == 0)).sum()), "malicious": int(((frame.split == name) & (frame.label == 1)).sum())} for name in ["development", "test"]},
        "actual_test_size": float(frame.split.eq("test").sum() / known.sum()),
    }
    return frame, manifest, metadata
