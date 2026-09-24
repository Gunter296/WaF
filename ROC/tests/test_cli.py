"""End-to-end contracts for the offline five-stage CLI and locked evaluation."""

from __future__ import annotations

import builtins
import copy
import json
from pathlib import Path
import re
import shutil

import numpy as np
import pandas as pd
import pytest
import yaml

from crs_eval import cli
from crs_eval.config import load_config
from crs_eval.io import load_data
from crs_eval.utils import read_json


REQUIRED_ARTIFACTS = {
    "data_quality.json", "normalized_data.csv", "excluded_records.csv",
    "split_manifest.csv", "development_score_metrics.csv",
    "development_threshold_candidates.csv", "policy_candidates.csv",
    "selected_policies.json", "test_metrics.csv", "test_predictions.csv",
    "false_positives.csv", "false_negatives.csv", "policy_disagreements.csv",
    "roc_curves.png", "roc_low_fpr.png", "precision_recall_curves.png",
    "policy_tradeoffs.png", "experiment_manifest.json", "report.html",
}


def _write_config(path: Path, settings: dict) -> None:
    path.write_text(yaml.safe_dump(settings, sort_keys=False), encoding="utf-8")


@pytest.fixture(scope="module")
def completed_experiments(tmp_path_factory):
    directory = tmp_path_factory.mktemp("cli-end-to-end")
    records = []
    for group in range(8):
        for position, label in enumerate([0, 0, 1, 1]):
            score = group % 3 if label == 0 else 2 + group % 5 + 4 * (position == 3)
            records.append({
                "transaction": {
                    "id": f"g{group}-request{position}", "is_interrupted": bool(label),
                    "request": {"uri": "/private/query?token=not-for-export", "method": "GET", "headers": {"Authorization": "secret-must-never-export"}},
                    "response": {"status": 403 if label else 200},
                },
                "run_id": "synthetic-run", "label": label, "group_id": f"family-{group}",
                "configuration_id": "synthetic-config", "dataset_source": "synthetic",
                "crs_score_summary": {"status": "partial"},
                "crs_scores": {"inbound": {"blocking": score, "threshold": 5}, "category": {"sqli": None if position == 0 and group % 2 == 0 else score}},
            })
    records.append({
        "transaction": {"id": "unknown-timeout", "is_interrupted": False, "response": {"status": 504}},
        "run_id": "synthetic-run", "label": "unknown", "group_id": "unknown-family",
        "configuration_id": "synthetic-config", "dataset_source": "synthetic",
        "timeout": True, "request_error": "synthetic timeout", "crs_score_summary": {"status": "partial"},
        "crs_scores": {"inbound": {"blocking": 99999, "threshold": 5}, "category": {"sqli": 99999}},
    })
    dataset = directory / "data.jsonl"
    dataset.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    settings = {
        "synthetic": True, "input": {"paths": ["data.jsonl"], "format": "jsonl"},
        "configuration_id": "synthetic-config", "output_path": "run-a", "duplicate_handling": "error",
        "features": ["inbound_blocking", "sqli"], "grouping": {"field": "group_id", "allow_request_fallback": False},
        "split": {"test_size": 0.25, "seed": 93}, "fpr_targets": [0, 0.5],
        "search": {"max_evaluations": 80, "seed": 93}, "bootstrap": {"iterations": 30, "seed": 93, "confidence": 0.95},
        "export": {"include_uri": False}, "collection_manifest": {"engine_mode": "DetectionOnly"},
        "policy_families": [{"name": "inbound_or_sqli", "expression": {"op": "or", "children": [
            {"feature": "inbound_blocking", "parameter": "total"}, {"feature": "sqli", "parameter": "sql"},
        ]}}],
    }
    config_paths = []
    for suffix in ["a", "b"]:
        run_settings = {**settings, "output_path": f"run-{suffix}"}
        path = directory / f"experiment-{suffix}.yaml"
        _write_config(path, run_settings)
        for command in ["validate", "split", "explore", "tune", "evaluate"]:
            assert cli.main([command, "--config", str(path)]) == 0
        config_paths.append(path)
    return {"directory": directory, "settings": settings, "configs": config_paths,
            "outputs": [directory / "run-a", directory / "run-b"]}


@pytest.fixture
def cloned_experiment(completed_experiments, tmp_path):
    source = completed_experiments["outputs"][0]
    output = tmp_path / "copied-output"
    shutil.copytree(source, output)
    # Source paths and all substantive config values remain unchanged; only
    # output and config-file location change, as explicitly allowed by provenance.
    settings = copy.deepcopy(completed_experiments["settings"])
    settings["input"]["paths"] = [str(completed_experiments["directory"] / "data.jsonl")]
    settings["output_path"] = str(output)
    path = tmp_path / "experiment.yaml"
    _write_config(path, settings)
    return path, output, settings


def test_five_commands_create_complete_offline_report(completed_experiments):
    output = completed_experiments["outputs"][0]
    assert REQUIRED_ARTIFACTS <= {file.name for file in output.iterdir()}
    assert all((output / name).stat().st_size > 0 for name in REQUIRED_ARTIFACTS)
    report = (output / "report.html").read_text(encoding="utf-8")
    assert "SYNTHETIC DEMONSTRATION" in report
    assert "NOT A REAL WAF BENCHMARK" in report
    assert report.count("data:image/png;base64,") == 4
    assert not re.search(r'(?:src|href)\s*=\s*["\'](?:https?:)?//', report, re.IGNORECASE)
    manifest = read_json(output / "experiment_manifest.json")
    assert manifest["stages"] == ["validate", "split", "explore", "tune", "evaluate"]
    assert manifest["synthetic"] is True
    for filename in ["normalized_data.csv", "test_predictions.csv", "false_positives.csv", "false_negatives.csv"]:
        text = (output / filename).read_text(encoding="utf-8")
        assert "secret-must-never-export" not in text
        assert "/private/query" not in text


def test_repeated_experiment_is_reproducible_and_strict_json(completed_experiments):
    first, second = completed_experiments["outputs"]
    for name in ["split_manifest.csv", "selected_policies.json", "policy_candidates.csv", "test_metrics.csv", "test_predictions.csv", "bootstrap_intervals.json"]:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
    locked = read_json(first / "selected_policies.json")
    json.dumps(locked, allow_nan=False)
    assert locked["search"]["evaluations"] <= 80
    assert locked["cohort_features"] == ["inbound_blocking", "inbound_threshold", "sqli"]


def test_comparison_cohort_groups_unknowns_and_counts_are_consistent(completed_experiments):
    output = completed_experiments["outputs"][0]
    split = pd.read_csv(output / "split_manifest.csv")
    assert not (set(split.loc[split.split == "test", "group_id"]) & set(split.loc[split.split == "development", "group_id"]))
    for name in ["development", "test"]:
        assert set(split.loc[split.split == name, "label"]) == {0, 1}
    normalized = pd.read_csv(output / "normalized_data.csv")
    timeout = normalized.loc[normalized.request_id == "unknown-timeout"].iloc[0]
    assert pd.isna(timeout["label"])
    assert bool(timeout["timeout"]) is True
    assert split.loc[split.request_id == "unknown-timeout", "split"].iloc[0] == "excluded"
    assert normalized.sqli.isna().sum() == 4
    quality = read_json(output / "data_quality.json")
    assert quality["source_timeouts"] == 1 and quality["source_request_errors"] == 1
    predictions = pd.read_csv(output / "test_predictions.csv")
    assert "unknown-timeout" not in set(predictions.request_id)
    assert predictions.sqli.notna().all()
    keysets = [frozenset(zip(frame.run_id, frame.request_id)) for _, frame in predictions.groupby("policy")]
    assert len(set(keysets)) == 1
    metrics = pd.read_csv(output / "test_metrics.csv")
    assert metrics.n.nunique() == 1
    assert metrics.n_positive.nunique() == 1 and metrics.n_negative.nunique() == 1
    for _, row in metrics.iterrows():
        policy = predictions[predictions.policy == row["policy"]]
        outcomes = policy.outcome.value_counts()
        for outcome in ["TP", "FP", "TN", "FN"]:
            assert row[outcome.lower()] == outcomes.get(outcome, 0)
        assert row["n"] == row["tp"] + row["fp"] + row["tn"] + row["fn"]
    thresholds = pd.read_csv(output / "development_threshold_candidates.csv")
    assert 99999 not in set(thresholds.threshold.dropna())


def test_changing_only_test_scores_cannot_change_tuned_candidates(completed_experiments, tmp_path):
    original_output = completed_experiments["outputs"][0]
    assignments = pd.read_csv(original_output / "split_manifest.csv")
    test_ids = set(assignments.loc[assignments.split == "test", "request_id"])
    source = completed_experiments["directory"] / "data.jsonl"
    records = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    for record in records:
        if record["transaction"]["id"] in test_ids:
            record["crs_scores"]["inbound"]["blocking"] += 100000
            if record["crs_scores"]["category"]["sqli"] is not None:
                record["crs_scores"]["category"]["sqli"] += 100000
    changed_source = tmp_path / "test-scores-changed.jsonl"
    changed_source.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    settings = copy.deepcopy(completed_experiments["settings"])
    settings["input"]["paths"] = [str(changed_source)]
    settings["output_path"] = str(tmp_path / "separate-experiment")
    path = tmp_path / "changed-test-config.yaml"
    _write_config(path, settings)
    assert cli.main(["split", "--config", str(path)]) == 0
    assert cli.main(["tune", "--config", str(path)]) == 0
    output = Path(settings["output_path"])
    assert (output / "split_manifest.csv").read_bytes() == (original_output / "split_manifest.csv").read_bytes()
    assert (output / "policy_candidates.csv").read_bytes() == (original_output / "policy_candidates.csv").read_bytes()
    changed_lock = read_json(output / "selected_policies.json")
    original_lock = read_json(original_output / "selected_policies.json")
    assert changed_lock["data_fingerprint"] != original_lock["data_fingerprint"]
    assert changed_lock["policies"] == original_lock["policies"]


def test_evaluate_uses_locked_policies_without_importing_or_calling_search(cloned_experiment, monkeypatch):
    path, output, _ = cloned_experiment
    import crs_eval.search as search_module

    def forbidden_tuning(*args, **kwargs):
        pytest.fail("evaluate must never call policy search")

    real_import = builtins.__import__

    def reject_search_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in {"search", "crs_eval.search"}:
            pytest.fail("evaluate must not import the tuning module")
        return real_import(name, globals, locals, fromlist, level)

    locked_before = (output / "selected_policies.json").read_bytes()
    monkeypatch.setattr(search_module, "search_policies", forbidden_tuning)
    monkeypatch.setattr(builtins, "__import__", reject_search_import)
    assert cli.main(["evaluate", "--config", str(path)]) == 0
    assert (output / "selected_policies.json").read_bytes() == locked_before


@pytest.mark.parametrize("artifact,expected", [
    ("selected_policies.json", "Locked policy artifact changed"),
    ("split_manifest.csv", "Split manifest was modified"),
])
def test_tampered_policy_or_split_is_rejected(cloned_experiment, capsys, artifact, expected):
    path, output, _ = cloned_experiment
    target = output / artifact
    target.write_bytes(target.read_bytes() + b"\n")
    metrics_before = (output / "test_metrics.csv").read_bytes()
    assert cli.main(["evaluate", "--config", str(path)]) == 2
    assert expected in capsys.readouterr().err
    assert (output / "test_metrics.csv").read_bytes() == metrics_before


def test_changed_configuration_refuses_to_overwrite_existing_results(cloned_experiment, capsys):
    path, output, settings = cloned_experiment
    original_manifest = (output / "experiment_manifest.json").read_bytes()
    settings["fpr_targets"] = [0.1]
    _write_config(path, settings)
    assert cli.main(["validate", "--config", str(path)]) == 2
    assert "Choose a new output_path" in capsys.readouterr().err
    assert (output / "experiment_manifest.json").read_bytes() == original_manifest


def test_evaluated_experiment_cannot_retune_or_resplit(cloned_experiment, capsys):
    path, output, _ = cloned_experiment
    locked_before = (output / "selected_policies.json").read_bytes()
    split_before = (output / "split_manifest.csv").read_bytes()
    assert cli.main(["tune", "--config", str(path)]) == 2
    assert "Refusing to retune" in capsys.readouterr().err
    assert cli.main(["split", "--config", str(path)]) == 2
    assert "Policies are already locked" in capsys.readouterr().err
    assert (output / "selected_policies.json").read_bytes() == locked_before
    assert (output / "split_manifest.csv").read_bytes() == split_before


@pytest.mark.parametrize("feature", ["uri", "http_status", "interrupted", "cve_id", "dataset_source", "label", "timeout"])
def test_configuration_rejects_metadata_decision_features(completed_experiments, tmp_path, feature):
    settings = copy.deepcopy(completed_experiments["settings"])
    settings["features"] = [feature]
    settings["policy_families"] = []
    path = tmp_path / "metadata-feature.yaml"
    _write_config(path, settings)
    with pytest.raises(ValueError, match="Only declared inbound scores"):
        load_config(path)


def test_configuration_rejects_declared_outbound_feature(completed_experiments, tmp_path):
    settings = copy.deepcopy(completed_experiments["settings"])
    settings["features"] = ["response_score"]
    settings["score_fields"] = ["response_score"]
    settings["feature_metadata"] = {"response_score": {"phase": "outbound", "meaning": "Response anomaly score"}}
    settings["policy_families"] = []
    path = tmp_path / "outbound-feature.yaml"
    _write_config(path, settings)
    with pytest.raises(ValueError, match="inbound"):
        load_config(path)


def test_duplicate_replay_join_fails_without_inferring_actual_from_http_status(completed_experiments, tmp_path):
    cfg = load_config(completed_experiments["configs"][0])
    frame, _, _ = load_data(cfg)
    cohort = frame[frame.label.notna()].iloc[:2].reset_index(drop=True)
    replay = tmp_path / "replay.csv"
    replay.write_text("run_id,request_id,actual_interrupted\n" + f"{cohort.iloc[0].run_id},{cohort.iloc[0].request_id},true\n" * 2, encoding="utf-8")
    cfg["replay"] = {"path": str(replay)}
    with pytest.raises(ValueError, match="one-to-many replay joins"):
        cli._interruption_report(cohort, {"example": np.array([True, False])}, cfg)
    cfg.pop("replay")
    cohort["interrupted"] = pd.array([pd.NA, pd.NA], dtype="boolean")
    cohort["http_status"] = [403, 200]
    comparison = cli._interruption_report(cohort, {"example": np.array([True, False])}, cfg)
    assert comparison.actual_interrupted.isna().all()
    assert comparison.prediction_matches_interruption.isna().all()
