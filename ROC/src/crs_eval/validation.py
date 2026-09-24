"""Dataset validation without inventing labels or filling missing scores."""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd


DEFAULT_MAPPING = {
    "request_id": "transaction.id", "timestamp": "@timestamp",
    "uri": "transaction.request.uri", "method": "transaction.request.method",
    "http_status": "transaction.response.status", "interrupted": "transaction.is_interrupted",
    "summary_status": "crs_score_summary.status", "inbound_blocking": "crs_scores.inbound.blocking",
    "inbound_detection": "crs_scores.inbound.detection", "inbound_threshold": "crs_scores.inbound.threshold",
    **{f"pl{i}": f"crs_scores.inbound.pl{i}" for i in range(1, 5)},
    **{name: f"crs_scores.category.{name}" for name in ("sqli", "xss", "rce", "lfi", "rfi", "phpi", "http", "sess")},
    **{name: name for name in ("run_id", "label", "dataset_source", "template_id", "cve_id", "group_id", "attack_category", "configuration_id", "request_error", "timeout")},
}
BUILTIN_SCORES = set(DEFAULT_MAPPING) - {
    "request_id", "timestamp", "uri", "method", "http_status", "interrupted", "summary_status",
    "run_id", "label", "dataset_source", "template_id", "cve_id", "group_id", "attack_category", "configuration_id", "request_error", "timeout",
}
FORBIDDEN_FEATURES = {
    "request_id", "run_id", "group_id", "timestamp", "uri", "method", "http_status", "interrupted", "label",
    "dataset_source", "template_id", "cve_id", "attack_category", "configuration_id", "summary_status", "inbound_threshold", "request_error", "timeout",
}
MISSING_WORDS = {"", "null", "none", "nan", "na", "n/a"}


class DataValidationError(ValueError):
    """Fatal validation issue, retaining reports for the CLI to export."""

    def __init__(self, message: str, quality: dict[str, Any] | None = None, excluded: pd.DataFrame | None = None):
        super().__init__(message)
        self.quality = quality or {"errors": [message], "warnings": []}
        self.excluded = excluded if excluded is not None else pd.DataFrame()


def is_missing(value: Any) -> bool:
    if value is None or value is pd.NA or value is pd.NaT:
        return True
    if isinstance(value, str):
        return value.strip().lower() in MISSING_WORDS
    return bool(pd.isna(value)) if np.isscalar(value) else False


def parse_label(value: Any) -> tuple[Any, bool]:
    if is_missing(value) or (isinstance(value, str) and value.strip().lower() == "unknown"):
        return pd.NA, False
    if isinstance(value, bool):
        return pd.NA, True
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return pd.NA, True
    if parsed in (0.0, 1.0):
        return int(parsed), False
    return pd.NA, True


def parse_boolean(value: Any) -> tuple[Any, bool]:
    if is_missing(value):
        return pd.NA, False
    if isinstance(value, (bool, np.bool_)):
        return bool(value), False
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "1.0"}:
        return True, False
    if normalized in {"false", "0", "0.0"}:
        return False, False
    return pd.NA, True


def score_fields(config: dict[str, Any]) -> list[str]:
    mapping = {**DEFAULT_MAPPING, **config.get("field_mapping", {})}
    fields = set(config.get("score_fields", [])) | (set(mapping) & BUILTIN_SCORES)
    fields.update(config.get("features", []))
    for name, specification in config.get("derived_features", {}).items():
        fields.add(name)
        if isinstance(specification, dict):
            fields.update(specification.get("sum", []))
    return sorted(fields)


def validate_feature_definitions(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    derived = config.get("derived_features", {})
    metadata = config.get("feature_metadata", {})
    inspected: set[str] = set()

    def check(feature: str, stack: set[str]) -> None:
        if feature in stack:
            errors.append(f"Cyclic derived feature definition: {feature}.")
            return
        if feature in inspected:
            return
        inspected.add(feature)
        if feature in FORBIDDEN_FEATURES:
            errors.append(f"Metadata/threshold field '{feature}' cannot be a decision feature.")
            return
        definition = metadata.get(feature, {})
        if definition.get("phase", "inbound") != "inbound":
            errors.append(f"Decision feature '{feature}' must explicitly be available in the inbound phase.")
        if feature in derived:
            specification = derived[feature]
            components = specification.get("sum") if isinstance(specification, dict) else None
            if not isinstance(components, list) or not components or not all(isinstance(x, str) for x in components):
                errors.append(f"Derived feature '{feature}' requires a nonempty explicit sum list.")
                return
            for component in components:
                check(component, stack | {feature})
            return
        phase = definition.get("phase", "inbound" if feature in BUILTIN_SCORES else None)
        if phase != "inbound":
            errors.append(f"Decision feature '{feature}' must explicitly be available in the inbound phase.")
        if feature not in BUILTIN_SCORES and not definition.get("meaning"):
            errors.append(f"Custom score '{feature}' needs feature_metadata.meaning.")

    for selected in config.get("features", []):
        check(selected, set())
    for name in derived:
        check(name, set())
    return errors


def add_quality_summaries(frame: pd.DataFrame, quality: dict[str, Any], scores: list[str]) -> None:
    quality["included_documents"] = len(frame)
    quality["unique_transactions"] = int(frame[["run_id", "request_id"]].drop_duplicates().shape[0])
    quality["labels"] = {"legitimate": int((frame.label == 0).sum()), "malicious": int((frame.label == 1).sum()), "unknown": int(frame.label.isna().sum())}
    quality["summary_status"] = {str(k): int(v) for k, v in frame.summary_status.fillna("missing").value_counts().items()}
    quality["missing_scores"] = {score: int(frame[score].isna().sum()) for score in scores}
    quality["score_fields"] = scores
    quality["constant_scores"] = [score for score in scores if frame[score].nunique(dropna=True) == 1]
    quality["excluded_features"] = {score: "all values missing" for score in scores if not frame[score].notna().any()}
    quality["score_statistics_by_label"] = {}
    for label, title in [(0, "legitimate"), (1, "malicious"), (None, "unknown")]:
        rows = frame.loc[frame.label.isna() if label is None else frame.label.eq(label).fillna(False)]
        quality["score_statistics_by_label"][title] = {}
        for score in scores:
            values = rows[score].dropna()
            quality["score_statistics_by_label"][title][score] = {
                "count": int(len(values)), "min": float(values.min()) if len(values) else None,
                "max": float(values.max()) if len(values) else None,
                "median": float(values.median()) if len(values) else None,
                **{f"p{p}": float(values.quantile(p / 100)) if len(values) else None for p in [5, 25, 75, 95, 99]},
            }
    quality["groups_by_dataset_configuration"] = [
        {"dataset_source": str(dataset), "configuration_id": str(configuration), "samples": len(rows), "groups": int(rows.group_id.nunique(dropna=True))}
        for (dataset, configuration), rows in frame.groupby(["dataset_source", "configuration_id"], dropna=False, sort=True)
    ]
    if quality["constant_scores"]:
        quality["warnings"].append("Constant score fields: " + ", ".join(quality["constant_scores"]))
    if quality["excluded_features"]:
        quality["warnings"].append("All-missing score fields are unavailable; missing values remain missing.")
    if quality["labels"]["unknown"]:
        quality["warnings"].append("Unknown labels are retained in quality reporting and excluded from supervised evaluation.")
