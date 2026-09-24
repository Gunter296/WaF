import csv
import json

import pandas as pd
import pytest

from crs_eval.io import load_data
from crs_eval.split import split_data
from crs_eval.validation import DataValidationError


def records():
    return [
        {"transaction.id": f"id-{i}", "run_id": "run", "label": i % 2,
         "group_id": f"family-{i // 2}", "configuration_id": "one", "dataset_source": "synthetic",
         "transaction.is_interrupted": "false" if i % 2 == 0 else "true",
         "crs_scores.inbound.blocking": i, "crs_scores.inbound.threshold": 5,
         "crs_scores.inbound.pl3": i, "crs_scores.inbound.pl4": 1,
         "crs_score_summary.status": "complete", "transaction.request.uri": "/sensitive?secret=x"}
        for i in range(8)
    ]


def save_config(tmp_path, rows=None, file_format="csv"):
    rows = records() if rows is None else rows
    path = tmp_path / f"data.{file_format}"
    if file_format == "csv":
        fields = sorted({key for row in rows for key in row})
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return {"input": {"paths": [str(path)], "format": file_format}, "features": ["inbound_blocking"],
            "configuration_id": "one", "grouping": {"field": "group_id"}, "split": {"test_size": 0.5, "seed": 19}}


def test_csv_dotted_and_nested_jsonl_are_equivalent(tmp_path):
    rows = records()
    csv_config = save_config(tmp_path, rows)
    nested = []
    for row in rows:
        record = {}
        for key, value in row.items():
            target = record
            for part in key.split(".")[:-1]:
                target = target.setdefault(part, {})
            target[key.split(".")[-1]] = value
        nested.append(record)
    json_config = save_config(tmp_path, nested, "jsonl")
    csv_frame, _, _ = load_data(csv_config)
    json_frame, _, _ = load_data(json_config)
    pd.testing.assert_frame_equal(csv_frame.drop(columns="source_file"), json_frame.drop(columns="source_file"))
    assert csv_frame.interrupted.tolist() == [False, True] * 4
    assert "uri" not in csv_frame


def test_missing_invalid_scores_not_imputed_and_partial_allowed(tmp_path):
    rows = records()
    rows[0]["crs_scores.inbound.blocking"] = ""
    rows[1]["crs_scores.inbound.blocking"] = "bad"
    rows[2]["crs_scores.inbound.blocking"] = "Infinity"
    rows[3]["crs_score_summary.status"] = "partial"
    frame, quality, _ = load_data(save_config(tmp_path, rows))
    assert frame.inbound_blocking.iloc[:3].isna().all()
    assert frame.inbound_blocking.iloc[3] == 3
    assert quality["non_numeric_scores"]["inbound_blocking"] == 2
    assert quality["missing_scores"]["inbound_blocking"] == 3
    assert quality["summary_status"]["partial"] == 1
    assert quality["excluded_features"]["sqli"] == "all values missing"


def test_unknown_kept_for_quality_and_excluded_from_supervised_split(tmp_path):
    rows = records()
    rows[0]["label"] = "unknown"
    frame, quality, excluded = load_data(save_config(tmp_path, rows))
    assert quality["labels"]["unknown"] == 1
    assert excluded.exclusion_reason.tolist() == ["unknown_label"]
    split, _, _ = split_data(frame, save_config(tmp_path, rows))
    assert split.loc[split.request_id.eq("id-0"), "split"].item() == "excluded"


@pytest.mark.parametrize("duplicate_policy, conflicting, raises", [("error", False, True), ("drop_identical", False, False), ("drop_identical", True, True), ("keep_first", True, False)])
def test_duplicate_handling_is_explicit_and_audited(tmp_path, duplicate_policy, conflicting, raises):
    rows = records()
    duplicate = dict(rows[0])
    if conflicting:
        duplicate["crs_scores.inbound.blocking"] = 99
    rows.append(duplicate)
    config = save_config(tmp_path, rows)
    config["duplicate_handling"] = duplicate_policy
    if raises:
        with pytest.raises(DataValidationError, match="Duplicate") as failure:
            load_data(config)
        assert failure.value.quality["duplicates"]["extra_records"] == 1
    else:
        frame, quality, excluded = load_data(config)
        assert len(frame) == 8
        assert quality["duplicates"]["conflicting_keys"] == int(conflicting)
        assert excluded.exclusion_reason.str.startswith("duplicate_").all()


def test_conflicting_duplicate_labels_fatal_even_keep_first(tmp_path):
    rows = records()
    rows.append({**rows[0], "label": 1})
    config = save_config(tmp_path, rows)
    config["duplicate_handling"] = "keep_first"
    with pytest.raises(DataValidationError, match="Conflicting labels"):
        load_data(config)


def test_label_join_preserves_transaction_correlation_and_unknowns(tmp_path):
    rows = records()
    for row in rows:
        row["label"] = "unknown"
    config = save_config(tmp_path, rows)
    label_file = tmp_path / "labels.jsonl"
    label_file.write_text("\n".join(json.dumps({"rid": f"id-{i}", "truth": i % 2}) for i in range(7)), encoding="utf-8")
    config["labels"] = {"path": str(label_file), "format": "jsonl", "keys": {"request_id": "rid"}, "label_field": "truth"}
    frame, quality, _ = load_data(config)
    assert frame.label.tolist()[:7] == [0, 1, 0, 1, 0, 1, 0]
    assert pd.isna(frame.label.iloc[7])
    assert quality["label_join_unmatched"] == 1


@pytest.mark.parametrize("duplicate, conflict", [(True, False), (False, True)])
def test_label_join_rejects_fanout_and_conflicting_inline_label(tmp_path, duplicate, conflict):
    config = save_config(tmp_path)
    labels = [{"rid": "id-0", "truth": 1 if conflict else 0}]
    if duplicate:
        labels.append(dict(labels[0]))
    path = tmp_path / "labels.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in labels), encoding="utf-8")
    config["labels"] = {"path": str(path), "format": "jsonl", "keys": {"request_id": "rid"}, "label_field": "truth"}
    with pytest.raises(DataValidationError, match="correlation keys|conflicting labels"):
        load_data(config)


def test_groups_disjoint_seed_reproducible_and_scores_not_used(tmp_path):
    config = save_config(tmp_path)
    frame, _, _ = load_data(config)
    first, manifest, metadata = split_data(frame, config)
    perturbed = frame.copy()
    perturbed["inbound_blocking"] = list(range(999, 991, -1))
    _, other_manifest, other_metadata = split_data(perturbed, config)
    pd.testing.assert_frame_equal(manifest, other_manifest)
    assert metadata["fingerprint"] == other_metadata["fingerprint"]
    assert metadata["data_fingerprint"] != other_metadata["data_fingerprint"]
    assert not set(first.loc[first.split.eq("development"), "group_id"]) & set(first.loc[first.split.eq("test"), "group_id"])
    assert first.groupby("split").label.nunique().to_dict() == {"development": 2, "test": 2}


def test_missing_group_needs_explicit_override(tmp_path):
    rows = records()
    rows[0]["group_id"] = ""
    config = save_config(tmp_path, rows)
    with pytest.raises(DataValidationError, match="Missing group_id"):
        load_data(config)
    config["grouping"]["allow_request_fallback"] = True
    frame, _, _ = load_data(config)
    split, _, metadata = split_data(frame, config)
    assert split.group_id.iloc[0].startswith("__request_fallback__")
    assert "leakage" in metadata["warnings"][0]


def test_insufficient_independent_groups_is_actionable(tmp_path):
    rows = records()
    for row in rows:
        row["group_id"] = f"label-{row['label']}"
    config = save_config(tmp_path, rows)
    frame, _, _ = load_data(config)
    with pytest.raises(DataValidationError, match="fewer than two groups"):
        split_data(frame, config)


def test_configuration_filter_required_and_audited(tmp_path):
    rows = records()
    rows[0]["configuration_id"] = "two"
    config = save_config(tmp_path, rows)
    del config["configuration_id"]
    with pytest.raises(DataValidationError, match="Select configuration_id"):
        load_data(config)
    config["configuration_id"] = "one"
    frame, quality, excluded = load_data(config)
    assert len(frame) == 7
    assert quality["configuration_counts_before_filter"] == {"one": 7, "two": 1}
    assert excluded.exclusion_reason.tolist() == ["configuration_filter"]


def test_derived_sum_preserves_missing_and_custom_group_mapping(tmp_path):
    rows = records()
    rows[0]["crs_scores.inbound.pl3"] = ""
    for row in rows:
        row["request_family"] = row.pop("group_id")
    config = save_config(tmp_path, rows)
    config["grouping"]["field"] = "request_family"
    config["derived_features"] = {"high_pl": {"sum": ["pl3", "pl4"]}}
    config["features"].append("high_pl")
    frame, _, _ = load_data(config)
    assert pd.isna(frame.high_pl.iloc[0])
    assert frame.high_pl.iloc[1] == 2
    assert frame.group_id.equals(frame.request_family)


def test_sensitive_mapping_and_uri_export_optin(tmp_path):
    rows = records()
    for row in rows:
        row["transaction.request.headers.Authorization"] = "Bearer SECRET"
        row["transaction.request.body"] = "SECRET BODY"
    config = save_config(tmp_path, rows)
    config["field_mapping"] = {"token_value": "transaction.request.headers.Authorization", "payload": "transaction.request.body"}
    frame, _, _ = load_data(config)
    assert {"token_value", "payload", "uri"}.isdisjoint(frame.columns)
    config["export"] = {"include_uri": True}
    frame, _, _ = load_data(config)
    assert "uri" in frame


def test_variable_threshold_requires_explanation_and_fixed_fallback_explicit(tmp_path):
    rows = records()
    rows[0]["crs_scores.inbound.threshold"] = ""
    config = save_config(tmp_path, rows)
    frame, _, _ = load_data(config)
    assert pd.isna(frame.inbound_threshold.iloc[0])
    config["baseline"] = {"fixed_threshold": 7}
    with pytest.raises(DataValidationError, match="Variable per-request"):
        load_data(config)
    config["baseline"]["variable_threshold_explanation"] = "Explicit fallback for one missing row; collected rows used 5."
    frame, _, _ = load_data(config)
    assert frame.inbound_threshold.iloc[0] == 7


@pytest.mark.parametrize("feature, metadata", [("http_status", {}), ("outbound_score", {"phase": "outbound", "meaning": "response anomaly"}), ("custom", {})])
def test_metadata_or_unexplained_scores_cannot_decide_policy(tmp_path, feature, metadata):
    config = save_config(tmp_path)
    config["features"] = [feature]
    config["feature_metadata"] = {feature: metadata}
    with pytest.raises(DataValidationError, match="decision feature|inbound phase|meaning"):
        load_data(config)


def test_single_class_stops_supervised_analysis(tmp_path):
    rows = records()
    for row in rows:
        row["label"] = 1
    with pytest.raises(DataValidationError, match="both legitimate"):
        load_data(save_config(tmp_path, rows))
