"""Offline UTF-8 CSV/JSONL input, configured label correlation, and normalization."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .validation import (
    DEFAULT_MAPPING, DataValidationError, add_quality_summaries, is_missing,
    parse_boolean, parse_label, score_fields, validate_feature_definitions,
)


def read_records(path: str | Path, file_format: str) -> list[dict[str, Any]]:
    path = Path(path)
    if file_format not in {"csv", "jsonl"}:
        raise DataValidationError(f"Unsupported input format '{file_format}'; use csv or jsonl.")
    with path.open(encoding="utf-8-sig", newline="") as handle:
        if file_format == "csv":
            reader = csv.DictReader(handle)
            if reader.fieldnames and len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise DataValidationError(f"Duplicate CSV column names in {path.name}.")
            records = list(reader)
            if any(None in record for record in records):
                raise DataValidationError(f"CSV rows contain more fields than their header in {path.name}.")
            return records
        records = []
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DataValidationError(f"Invalid JSON at {path.name}:{line_number}: {exc.msg}.") from exc
            if not isinstance(record, dict):
                raise DataValidationError(f"Expected a JSON object at {path.name}:{line_number}.")
            records.append(record)
        return records


def mapped_value(record: dict[str, Any], external: str) -> Any:
    """An exact dotted column name takes precedence over nested traversal."""
    if external in record:
        return record[external]
    value: Any = record
    for segment in external.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def _sensitive_field(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(part in lowered for part in ("authorization", "cookie", "body", "headers", "raw_request", "raw_response"))


def _text(value: Any) -> Any:
    return None if is_missing(value) else str(value).strip()


_URI_CVE_PREFIX = re.compile(r"^/?(?P<cve>CVE-\d{4}-\d+?)/(?P<uri>.+)$", re.IGNORECASE)


def _split_uri_cve_prefix(uri: Any) -> tuple[Any, str | None]:
    """Remove only an explicit leading CVE-ID path segment; never infer labels."""
    if is_missing(uri):
        return uri, None
    text = str(uri).strip()
    match = _URI_CVE_PREFIX.fullmatch(text)
    if not match:
        return uri, None
    return match.group("uri"), match.group("cve").upper()


def _failure(quality: dict[str, Any], excluded: list[dict[str, Any]]) -> None:
    raise DataValidationError(" ".join(quality["errors"]), quality, pd.DataFrame(excluded))


def _join_labels(frame: pd.DataFrame, config: dict[str, Any], quality: dict[str, Any]) -> pd.DataFrame:
    specification = config.get("labels")
    quality["label_join_unmatched"] = 0
    quality["label_conflicts"] = 0
    if not specification:
        return frame
    keys = specification.get("keys", {})
    if not isinstance(keys, dict) or not keys:
        quality["errors"].append("labels.keys must map normalized request correlation fields to external label fields.")
        return frame
    if set(keys) <= {"cve_id", "timestamp", "template_id"}:
        quality["errors"].append("Label joins require explicit request correlation keys, not only CVE/template/timestamp.")
        return frame
    if any(key not in frame for key in keys):
        quality["errors"].append("Some normalized label join keys are absent from field_mapping.")
        return frame
    records = read_records(specification["path"], specification.get("format", "csv"))
    label_column = specification.get("label_field", "label")
    label_lookup: dict[tuple[Any, ...], Any] = {}
    duplicate_keys = 0
    bad_labels = 0
    missing_keys = 0
    for record in records:
        key = tuple(_text(mapped_value(record, external)) for external in keys.values())
        if any(value is None for value in key):
            missing_keys += 1
            continue
        label, invalid = parse_label(mapped_value(record, label_column))
        bad_labels += int(invalid)
        if key in label_lookup:
            duplicate_keys += 1
            old_label = label_lookup[key]
            if not is_missing(old_label) and not is_missing(label) and old_label != label:
                quality["label_conflicts"] += 1
        else:
            label_lookup[key] = label
    quality["label_file_duplicate_keys"] = duplicate_keys
    quality["label_file_missing_keys"] = missing_keys
    if duplicate_keys:
        quality["errors"].append(f"Label file has {duplicate_keys} duplicate correlation keys; expected a many-to-one join.")
    if bad_labels:
        quality["errors"].append(f"Label file contains {bad_labels} invalid labels; expected 0, 1, or unknown.")
    if missing_keys:
        quality["warnings"].append(f"{missing_keys} label records have missing correlation keys and cannot be joined.")
    assigned: list[Any] = []
    for _, row in frame.iterrows():
        key = tuple(_text(row[field]) for field in keys)
        existing, invalid = parse_label(row.get("label"))
        if invalid:
            quality["invalid_inline_labels"] = quality.get("invalid_inline_labels", 0) + 1
        if any(value is None for value in key) or key not in label_lookup:
            quality["label_join_unmatched"] += 1
            assigned.append(existing)
            continue
        matched = label_lookup[key]
        if not is_missing(existing) and not is_missing(matched) and existing != matched:
            quality["label_conflicts"] += 1
        assigned.append(matched if not is_missing(matched) else existing)
    frame["label"] = pd.array(assigned, dtype="Int64")
    if quality["label_conflicts"]:
        quality["errors"].append(f"Found {quality['label_conflicts']} conflicting labels.")
    if quality.get("invalid_inline_labels"):
        quality["errors"].append("Invalid inline labels were encountered during label joining.")
    return frame


def load_data(config: dict[str, Any]) -> tuple[pd.DataFrame, dict[str, Any], pd.DataFrame]:
    """Return normalized rows, a JSON-safe quality report, and audited exclusions.

    Fatal issues raise :class:`DataValidationError` with ``quality`` and
    ``excluded`` reports. Original bodies, headers and cookies are never retained.
    URI is retained only with ``export.include_uri: true``.
    """
    quality: dict[str, Any] = {"errors": [], "warnings": [], "total_documents": 0}
    excluded: list[dict[str, Any]] = []
    quality["errors"].extend(validate_feature_definitions(config))
    mapping = {**DEFAULT_MAPPING, **config.get("field_mapping", {})}
    scores = score_fields(config)
    for score in scores:
        if score not in config.get("derived_features", {}):
            mapping.setdefault(score, score)
    group_field = config.get("grouping", {}).get("field", "group_id")
    mapping.setdefault(group_field, group_field)
    for key in (config.get("labels") or {}).get("keys", {}):
        mapping.setdefault(key, key)
    mapping = {key: value for key, value in mapping.items() if not _sensitive_field(key) and not _sensitive_field(str(value))}
    include_uri = bool(config.get("export", {}).get("include_uri", False))
    rows = []
    input_config = config.get("input", {})
    paths = input_config.get("paths", [])
    if isinstance(paths, (str, Path)):
        paths = [paths]
    if not paths:
        quality["errors"].append("input.paths must contain at least one offline dataset file.")
    for path in paths:
        records = read_records(path, input_config.get("format", "csv"))
        for row_number, record in enumerate(records, 1):
            row = {internal: mapped_value(record, external) for internal, external in mapping.items()}
            for key, value in list(row.items()):
                if isinstance(value, (dict, list)):
                    quality["errors"].append(f"Mapped field '{key}' must be scalar ({Path(path).name}, record {row_number}).")
                    row[key] = None
            row["source_file"] = Path(path).name
            row["source_record"] = row_number
            rows.append(row)
    quality["total_documents"] = len(rows)
    if not rows:
        quality["errors"].append("Dataset is empty.")
        _failure(quality, excluded)
    frame = pd.DataFrame(rows)
    for column in ["request_id", "run_id", "group_id", "dataset_source", "configuration_id", "summary_status", "uri", "cve_id"]:
        if column not in frame:
            frame[column] = None
        frame[column] = frame[column].map(_text)
    if group_field != "group_id":
        frame["group_id"] = frame[group_field].map(_text)
    quality["configuration_counts_before_filter"] = {str(k): int(v) for k, v in frame.configuration_id.fillna("missing").value_counts().items()}
    selected_configuration = config.get("configuration_id")
    if selected_configuration is None:
        configurations = frame.configuration_id.dropna().unique()
        if len(configurations) != 1 or frame.configuration_id.isna().any():
            quality["errors"].append("Select configuration_id explicitly when configuration IDs are mixed or missing; map a known configuration to every request.")
    else:
        mask = frame.configuration_id.eq(str(selected_configuration))
        for record in frame.loc[~mask].to_dict("records"):
            excluded.append({**record, "exclusion_reason": "configuration_filter"})
        frame = frame.loc[mask].copy()
        if frame.empty:
            quality["errors"].append(f"No requests match configuration_id '{selected_configuration}'.")
    quality["uri_cve_prefix_extracted"] = 0
    quality["uri_cve_id_conflicts"] = 0
    if config.get("uri_cve_prefix", True) and "uri" in frame:
        for index, uri in frame["uri"].items():
            normalized_uri, prefixed_cve = _split_uri_cve_prefix(uri)
            if prefixed_cve is None:
                continue
            quality["uri_cve_prefix_extracted"] += 1
            existing_cve = _text(frame.at[index, "cve_id"])
            if existing_cve is None:
                frame.at[index, "cve_id"] = prefixed_cve
            elif existing_cve.upper() != prefixed_cve:
                quality["uri_cve_id_conflicts"] += 1
            frame.at[index, "uri"] = normalized_uri
        if quality["uri_cve_prefix_extracted"]:
            quality["warnings"].append(
                f"Removed a leading CVE-ID URI segment from {quality['uri_cve_prefix_extracted']} requests; "
                "the prefix is retained as cve_id metadata and never used as a decision feature."
            )
        if quality["uri_cve_id_conflicts"]:
            quality["warnings"].append(
                f"{quality['uri_cve_id_conflicts']} URI CVE prefixes disagree with explicit cve_id values; "
                "the explicit cve_id field was retained."
            )
    if not include_uri and "uri" in frame:
        frame = frame.drop(columns=["uri"])
    quality["configuration_id"] = str(selected_configuration) if selected_configuration is not None else (str(frame.configuration_id.iloc[0]) if len(frame) else None)
    if frame.request_id.isna().any():
        quality["errors"].append(f"{int(frame.request_id.isna().sum())} requests lack request_id; map a transaction ID.")
    if frame.run_id.isna().any():
        quality["warnings"].append("Missing run_id mapped to 'unspecified'; provide run_id to distinguish collection runs.")
        frame["run_id"] = frame.run_id.fillna("unspecified")
    frame["dataset_source"] = frame.dataset_source.fillna("unspecified")
    frame = _join_labels(frame, config, quality)
    parsed_labels = frame.label.map(parse_label)
    invalid_labels = sum(int(item[1]) for item in parsed_labels)
    quality["invalid_labels"] = invalid_labels
    if invalid_labels:
        quality["errors"].append(f"Found {invalid_labels} invalid labels; expected numeric 0, 1, or unknown.")
    frame["label"] = pd.array([item[0] for item in parsed_labels], dtype="Int64")
    quality["non_numeric_scores"] = {}
    for score in scores:
        original = frame[score] if score in frame else pd.Series(None, index=frame.index, dtype=object)
        numeric = pd.to_numeric(original, errors="coerce")
        numeric = numeric.mask(original.map(lambda value: isinstance(value, (bool, np.bool_))))
        numeric = numeric.astype(float).where(np.isfinite(numeric), np.nan)
        nonnumeric = (~original.map(is_missing) & numeric.isna()).sum()
        quality["non_numeric_scores"][score] = int(nonnumeric)
        frame[score] = numeric
    pending = dict(config.get("derived_features", {}))
    completed = set(scores) - set(pending)
    while pending:
        progressed = False
        for name, specification in list(pending.items()):
            components = specification.get("sum", []) if isinstance(specification, dict) else []
            if components and all(component in completed for component in components):
                values = frame[components].sum(axis=1, min_count=len(components))
                overflowed = values.notna() & ~np.isfinite(values)
                quality["non_numeric_scores"][name] += int(overflowed.sum())
                frame[name] = values.where(np.isfinite(values), np.nan)
                completed.add(name)
                del pending[name]
                progressed = True
        if not progressed:
            quality["errors"].append("Derived features have invalid or cyclic dependencies.")
            break
    interrupted = frame.interrupted.map(parse_boolean)
    frame["interrupted"] = pd.array([item[0] for item in interrupted], dtype="boolean")
    quality["invalid_interrupted_values"] = sum(int(item[1]) for item in interrupted)
    frame["http_status"] = pd.to_numeric(frame.http_status, errors="coerce")
    errors_recorded = ~frame.request_error.map(is_missing)
    timeouts_recorded = frame.timeout.map(parse_boolean)
    frame["timeout"] = pd.array([item[0] for item in timeouts_recorded], dtype="boolean")
    quality["source_request_errors"] = int(errors_recorded.sum())
    quality["source_timeouts"] = int(frame.timeout.fillna(False).sum())
    if quality["invalid_interrupted_values"]:
        quality["warnings"].append("Invalid interrupted values remain unknown; only true/false or 1/0 are accepted.")
    if any(quality["non_numeric_scores"].values()):
        quality["warnings"].append("Invalid/non-finite numeric scores remain missing and cannot enter a complete-case cohort.")
    baseline = config.get("baseline", {})
    fixed = baseline.get("fixed_threshold")
    if fixed is not None:
        try:
            fixed = float(fixed)
            if not np.isfinite(fixed):
                raise ValueError
            frame["inbound_threshold"] = frame.inbound_threshold.fillna(fixed)
            quality["fixed_threshold_fallback"] = fixed
        except (TypeError, ValueError):
            quality["errors"].append("baseline.fixed_threshold must be a finite number.")
    if frame.inbound_threshold.nunique(dropna=True) > 1 and not (baseline.get("variable_threshold_explanation") or config.get("collection_manifest", {}).get("variable_threshold_explanation")):
        quality["errors"].append("Variable per-request inbound_threshold requires baseline.variable_threshold_explanation or an explanation in collection_manifest.")
    quality["baseline_missing_thresholds"] = int(frame.inbound_threshold.isna().sum())
    if quality["baseline_missing_thresholds"]:
        quality["warnings"].append("Some requests lack baseline thresholds; declare a fixed fallback or these requests leave the common cohort.")
    duplicate_policy = config.get("duplicate_handling", "error")
    quality["duplicate_handling"] = duplicate_policy
    if duplicate_policy not in {"error", "drop_identical", "keep_first"}:
        quality["errors"].append("duplicate_handling must be error, drop_identical, or keep_first.")
    duplicates = {"duplicate_keys": 0, "extra_records": 0, "identical_extra_records": 0, "conflicting_keys": 0}
    to_drop: list[int] = []
    compared_columns = [column for column in frame.columns if column not in {"source_file", "source_record"}]
    for _, group in frame.groupby(["run_id", "request_id"], dropna=False, sort=False):
        if len(group) < 2:
            continue
        duplicates["duplicate_keys"] += 1
        duplicates["extra_records"] += len(group) - 1
        distinct = group[compared_columns].drop_duplicates()
        identical = len(distinct) == 1
        duplicates["identical_extra_records"] += len(group) - len(distinct)
        duplicates["conflicting_keys"] += int(not identical)
        if group.label.dropna().nunique() > 1:
            quality["label_conflicts"] += 1
            quality["errors"].append("Conflicting labels for a duplicate (run_id, request_id) key.")
        if duplicate_policy == "error" or (duplicate_policy == "drop_identical" and not identical):
            quality["errors"].append("Duplicate transaction keys found; select an explicit permitted duplicate policy or repair conflicting records.")
        elif duplicate_policy == "keep_first" or (duplicate_policy == "drop_identical" and identical):
            for index, record in group.iloc[1:].iterrows():
                to_drop.append(index)
                excluded.append({**record.to_dict(), "exclusion_reason": "duplicate_identical" if identical else "duplicate_keep_first_conflict"})
    frame = frame.drop(index=to_drop).reset_index(drop=True)
    quality["duplicates"] = duplicates
    if frame.group_id.isna().any() and not config.get("grouping", {}).get("allow_request_fallback", False):
        quality["errors"].append("Missing group_id: configure grouping.field or explicitly enable grouping.allow_request_fallback (leakage risk).")
    if frame.label.dropna().nunique() < 2:
        quality["errors"].append("Supervised ROC/tuning requires both legitimate (0) and malicious (1) requests.")
    for record in frame.loc[frame.label.isna()].to_dict("records"):
        excluded.append({**record, "exclusion_reason": "unknown_label"})
    add_quality_summaries(frame, quality, scores)
    quality["excluded_record_count"] = len(excluded)
    quality["errors"] = list(dict.fromkeys(quality["errors"]))
    if quality["errors"]:
        _failure(quality, excluded)
    return frame, quality, pd.DataFrame(excluded, columns=list(frame.columns) + ["exclusion_reason"])
