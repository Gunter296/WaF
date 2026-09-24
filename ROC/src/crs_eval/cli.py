"""Five explicit offline stages; evaluate never performs policy selection."""
from __future__ import annotations

import argparse
import copy
import importlib.metadata
from pathlib import Path
import sys

import numpy as np
import pandas as pd

from .config import load_config
from .io import load_data
from .metrics import common_cohort, confusion_metrics, paired_group_bootstrap, require_two_classes
from .policies import evaluate_policy, required_features, template_features
from .reporting import plot_scores, plot_tradeoffs, render_report
from .split import split_data
from .utils import file_hash, fingerprint_dataframe, object_hash, read_json, write_csv, write_json

BASELINE = "crs_anomaly_baseline_simulated"


def _provenance(cfg):
    paths = list(cfg["input"]["paths"])
    for key in ("labels", "replay"):
        if cfg.get(key):
            paths.append(cfg[key]["path"])
    return {str(path): file_hash(path) for path in paths}


def _save_manifest(out, manifest):
    write_json(out / "experiment_manifest.json", manifest)


def _exclusions(out, frame, stage):
    frame = frame.copy()
    if "stage" not in frame:
        frame["stage"] = stage
    if len(frame.columns) == 1:
        frame = pd.DataFrame(columns=["run_id", "request_id", "exclusion_reason", "stage"])
    write_csv(out / f"excluded_{stage}.csv", frame)
    frames = [pd.read_csv(p, dtype=str, keep_default_na=False) for p in sorted(out.glob("excluded_*.csv")) if p.name != "excluded_records.csv"]
    write_csv(out / "excluded_records.csv", pd.concat(frames, ignore_index=True) if frames else frame)


def _prepare(cfg):
    out = Path(cfg["output_path"])
    manifest_path = out / "experiment_manifest.json"
    hashes = _provenance(cfg)
    if manifest_path.exists():
        manifest = read_json(manifest_path)
        if manifest.get("config_hash") != cfg["_config_hash"] or manifest.get("source_hashes") != hashes:
            raise ValueError("Output directory belongs to different configuration/data. Choose a new output_path; existing experiment was not overwritten.")
    else:
        if out.exists() and any(out.iterdir()):
            raise ValueError("Output directory is nonempty without an experiment manifest. Choose a new output_path.")
        out.mkdir(parents=True, exist_ok=True)
        manifest = {"schema_version": 1, "config_hash": cfg["_config_hash"], "source_hashes": hashes, "synthetic": cfg["synthetic"], "collection_manifest": cfg["collection_manifest"], "stages": [], "warnings": [], "versions": {p: importlib.metadata.version(p) for p in ["numpy", "pandas", "scikit-learn", "matplotlib", "PyYAML"]}, "config": {k: v for k, v in cfg.items() if not k.startswith("_")}}
        _save_manifest(out, manifest)
    try:
        data, quality, excluded = load_data(cfg)
    except ValueError as exc:
        if hasattr(exc, "quality"):
            write_json(out / "data_quality.json", exc.quality)
            _exclusions(out, exc.excluded, "validation")
        raise
    fingerprint = fingerprint_dataframe(data)
    if manifest.get("data_fingerprint", fingerprint) != fingerprint:
        raise ValueError("Normalized data differs from this experiment; use a new output_path")
    manifest["data_fingerprint"] = fingerprint
    write_json(out / "data_quality.json", quality)
    write_csv(out / "normalized_data.csv", data)
    _exclusions(out, excluded, "validation")
    _save_manifest(out, manifest)
    return out, manifest, data, quality


def _complete(stage, out, manifest, artifacts=()):
    if stage not in manifest["stages"]:
        manifest["stages"].append(stage)
    manifest.setdefault("artifact_hashes", {}).update({name: file_hash(out / name) for name in artifacts})
    _save_manifest(out, manifest)


def _with_split(out, manifest, data):
    path = out / "split_manifest.csv"
    if "split" not in manifest["stages"] or not path.exists():
        raise ValueError("Run crs-eval split first")
    if file_hash(path) != manifest["artifact_hashes"]["split_manifest.csv"]:
        raise ValueError("Split manifest was modified; refusing to evaluate a different split")
    assignments = pd.read_csv(path, dtype=str, keep_default_na=False)
    keys = ["run_id", "request_id"]
    subset = assignments[keys + ["group_id", "split"]]
    result = data.drop(columns=["group_id"]).merge(subset, on=keys, how="left", validate="one_to_one")
    if result["split"].isna().any():
        raise ValueError("Split manifest does not cover normalized requests")
    return result


def _baseline(cfg):
    # The loader fills only absent per-row thresholds from the explicit fallback.
    # Always retain existing per-row thresholds, even when a fallback is supplied.
    return {"baseline": True, "fixed_threshold": None}


def _active_features(development, cfg):
    active = copy.deepcopy(cfg)
    excluded = {feature: "all missing on development" for feature in cfg["features"] if feature not in development or development[feature].isna().all()}
    active["features"] = [f for f in cfg["features"] if f not in excluded]
    if not active["features"]:
        raise ValueError("All configured scores are missing on development; no threshold analysis is possible")
    skipped_families = {}
    families = []
    for family in cfg["policy_families"]:
        missing = template_features(family["expression"]) & set(excluded)
        if missing:
            skipped_families[family["name"]] = f"Required development scores all missing: {sorted(missing)}"
        else:
            families.append(family)
    active["policy_families"] = families
    return active, {"scores": excluded, "families": skipped_families}


def command_validate(cfg):
    out, manifest, data, quality = _prepare(cfg)
    _complete("validate", out, manifest, ["normalized_data.csv", "data_quality.json"])
    return {"stage": "validate", "transactions": len(data), "output": str(out)}


def command_split(cfg):
    out, manifest, data, quality = _prepare(cfg)
    assigned, split_manifest, metadata = split_data(data, cfg)
    if "tune" in manifest["stages"]:
        raise ValueError("Policies are already locked; use a new output_path to create a new split")
    write_csv(out / "split_manifest.csv", split_manifest)
    manifest["split"] = metadata
    _complete("split", out, manifest, ["split_manifest.csv"])
    return {"stage": "split", "split": metadata, "output": str(out)}


def command_explore(cfg):
    from .roc import analyze_scores
    out, manifest, data, quality = _prepare(cfg)
    assigned = _with_split(out, manifest, data)
    development = assigned[assigned["split"] == "development"]
    metrics, thresholds, curves = analyze_scores(development, cfg["features"], cfg["fpr_targets"])
    write_csv(out / "development_score_metrics.csv", metrics)
    write_csv(out / "development_threshold_candidates.csv", thresholds)
    plot_scores(curves, out, max(0.05, min(1, max(cfg["fpr_targets"]) * 2)))
    _complete("explore", out, manifest, ["development_score_metrics.csv", "development_threshold_candidates.csv"])
    return {"stage": "explore", "development_n": len(development), "output": str(out)}


def command_tune(cfg):
    from .search import search_policies
    out, manifest, data, quality = _prepare(cfg)
    if "evaluate" in manifest["stages"]:
        raise ValueError("Test has already been evaluated. Refusing to retune this experiment; keep the locked policies.")
    assigned = _with_split(out, manifest, data)
    development = assigned[assigned["split"] == "development"]
    active, excluded_features = _active_features(development, cfg)
    required = set(active["features"]) | required_features(_baseline(cfg))
    for family in active["policy_families"]:
        required |= template_features(family["expression"])
    cohort, coverage, excluded = common_cohort(development, sorted(required))
    require_two_classes(cohort["label"], "Development common comparison cohort")
    candidates, selected, search_metadata = search_policies(cohort, active)
    baseline = {"name": BASELINE, "family": "baseline", "selection_scope": "baseline", "fpr_target": None, "expression": _baseline(cfg), "configured_fixed_threshold_fallback": cfg["baseline"].get("fixed_threshold"), "required_features": sorted(required_features(_baseline(cfg))), "development_metrics": confusion_metrics(cohort["label"], evaluate_policy(cohort, _baseline(cfg)))}
    locked = {"schema_version": 1, "config_hash": cfg["_config_hash"], "data_fingerprint": manifest["data_fingerprint"], "split_fingerprint": manifest["artifact_hashes"]["split_manifest.csv"], "seed": cfg["search"]["seed"], "cohort_features": sorted(required), "development_coverage": coverage, "excluded_features": excluded_features, "search": search_metadata, "policies": [baseline, *selected]}
    locked["policy_lock"] = object_hash(locked)
    write_json(out / "selected_policies.json", locked)
    write_csv(out / "policy_candidates.csv", candidates)
    write_csv(out / "policy_pareto.csv", candidates[candidates["pareto"]])
    _exclusions(out, excluded, "development")
    plot_tradeoffs(candidates, out)
    manifest["development_coverage"] = coverage
    _complete("tune", out, manifest, ["selected_policies.json", "policy_candidates.csv", "policy_pareto.csv"])
    return {"stage": "tune", "evaluations": search_metadata["evaluations"], "selected": len(selected), "common_development_n": len(cohort), "output": str(out)}


def _group_results(cohort, predictions, cfg):
    rows = []
    stratify = ["dataset_source", "configuration_id", "inbound_threshold"]
    if cfg["collection_manifest"].get("attack_category_label_source"):
        stratify.append("attack_category")
    for column in stratify:
        if column not in cohort:
            continue
        for value, indices in cohort.groupby(column, dropna=False, sort=True).groups.items():
            position = cohort.index.get_indexer(indices)
            for name, predicted in predictions.items():
                rows.append({"policy": name, "split": "test", "cohort": "common_comparison_stratum", "grouping": column, "group_value": str(value), **confusion_metrics(cohort.loc[indices, "label"], predicted[position])})
    if "attack_category" in stratify:
        for category in cohort.loc[cohort["label"] == 1, "attack_category"].dropna().unique():
            mask = ((cohort["label"] == 0) | ((cohort["label"] == 1) & (cohort["attack_category"] == category))).to_numpy(dtype=bool)
            for name, predicted in predictions.items():
                rows.append({"policy": name, "split": "test", "cohort": "common_comparison_attack_vs_legitimate", "grouping": "attack_vs_legitimate", "group_value": str(category), **confusion_metrics(cohort.loc[mask, "label"], predicted[mask])})
    return pd.DataFrame(rows)


def _interruption_report(cohort, predictions, cfg):
    columns = [c for c in ["run_id", "request_id", "interrupted", "http_status"] if c in cohort]
    observed = cohort[columns].copy()
    observed["actual_interruption_source"] = "audit log interrupted field; not a ground truth label"
    if cfg.get("replay"):
        spec = cfg["replay"]
        replay = pd.read_csv(spec["path"], dtype=str, keep_default_na=False)
        keys = spec.get("keys", {"run_id": "run_id", "request_id": "request_id"})
        if not {"run_id", "request_id"} <= set(keys):
            raise ValueError("Replay correlation requires configured run_id and request_id keys")
        actual_field = spec.get("interrupted_field", "actual_interrupted")
        rename = {external: internal for internal, external in keys.items()}
        rename[actual_field] = "replay_interrupted"
        replay = replay[list(rename)].rename(columns=rename)
        if replay.duplicated(list(keys)).any():
            raise ValueError("Replay keys must be unique; one-to-many replay joins are not allowed")
        parsed = replay["replay_interrupted"].str.strip().str.lower().map({"true": True, "false": False, "1": True, "0": False, "": pd.NA, "null": pd.NA})
        invalid = parsed.isna() & ~replay["replay_interrupted"].str.strip().str.lower().isin(["", "null"])
        if invalid.any():
            raise ValueError("Replay interruption must be boolean; HTTP status is not interpreted as a WAF block")
        replay["replay_interrupted"] = parsed.astype("boolean")
        observed = observed.merge(replay, on=list(keys), how="left", validate="one_to_one")
        actual = observed["replay_interrupted"].astype("boolean")
        observed["actual_interruption_source"] = spec.get("description", "Explicit separately supplied replay interruption; not a ground truth label")
    else:
        actual = observed.get("interrupted", pd.Series(pd.NA, index=observed.index, dtype="boolean")).astype("boolean")
    frames = []
    for name, predicted in predictions.items():
        frame = observed.copy()
        frame["policy"] = name
        frame["split"] = "test"
        frame["cohort"] = "common_comparison"
        frame["predicted_block"] = predicted
        frame["actual_interrupted"] = actual
        frame["prediction_matches_interruption"] = pd.array(predicted, dtype="boolean") == actual
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def command_evaluate(cfg):
    out, manifest, data, quality = _prepare(cfg)
    if "tune" not in manifest["stages"]:
        raise ValueError("Run crs-eval tune to lock policies before evaluate")
    if "explore" not in manifest["stages"]:
        raise ValueError("Run crs-eval explore to generate development score analysis before the final report")
    path = out / "selected_policies.json"
    if file_hash(path) != manifest["artifact_hashes"]["selected_policies.json"]:
        raise ValueError("Locked policy artifact changed; refusing evaluation")
    locked = read_json(path)
    if object_hash({k: v for k, v in locked.items() if k != "policy_lock"}) != locked["policy_lock"]:
        raise ValueError("Invalid policy lock")
    for key, expected in [("config_hash", cfg["_config_hash"]), ("data_fingerprint", manifest["data_fingerprint"]), ("split_fingerprint", manifest["artifact_hashes"]["split_manifest.csv"])]:
        if locked[key] != expected:
            raise ValueError(f"Locked policy provenance mismatch: {key}")
    assigned = _with_split(out, manifest, data)
    test = assigned[assigned["split"] == "test"]
    cohort, coverage, excluded = common_cohort(test, locked["cohort_features"])
    require_two_classes(cohort["label"], "Test common comparison cohort")
    cohort = cohort.reset_index(drop=True)
    labels = cohort["label"].to_numpy(dtype=int)
    predictions = {p["name"]: evaluate_policy(cohort, p["expression"]) for p in locked["policies"]}
    baseline_metrics = confusion_metrics(labels, predictions[BASELINE])
    rows, prediction_frames, disagreements = [], [], []
    for policy in locked["policies"]:
        name = policy["name"]
        prediction = predictions[name]
        metrics = confusion_metrics(labels, prediction)
        target = policy["fpr_target"]
        rows.append({"policy": name, "family": policy["family"], "split": "test", "cohort": "common_comparison", "development_fpr_target": target, **metrics, "coverage": coverage["coverage"], "delta_recall_vs_baseline": metrics["recall"] - baseline_metrics["recall"], "delta_fpr_vs_baseline": metrics["fpr"] - baseline_metrics["fpr"], "test_fpr_target_violated": None if target is None else metrics["fpr"] > target})
        frame = cohort.copy()
        frame["policy"] = name
        frame["cohort"] = "common_comparison"
        frame["predicted_block"] = prediction
        frame["baseline_predicted_block"] = predictions[BASELINE]
        frame["outcome"] = np.where(prediction, np.where(labels == 1, "TP", "FP"), np.where(labels == 1, "FN", "TN"))
        prediction_frames.append(frame)
        if name != BASELINE:
            changed = frame[prediction != predictions[BASELINE]].copy()
            changed["disagreement"] = np.where(changed["predicted_block"].to_numpy() == changed["label"].to_numpy(), "policy_correct_baseline_wrong", "baseline_correct_policy_wrong")
            disagreements.append(changed)
    metrics = pd.DataFrame(rows)
    predictions_table = pd.concat(prediction_frames, ignore_index=True)
    uncertainty = paired_group_bootstrap(labels, predictions, cohort["group_id"].to_numpy(), BASELINE, **cfg["bootstrap"])
    grouped = _group_results(cohort, predictions, cfg)
    interruption = _interruption_report(cohort, predictions, cfg)
    tables = {"test_metrics.csv": metrics, "test_predictions.csv": predictions_table, "false_positives.csv": predictions_table[predictions_table["outcome"] == "FP"], "false_negatives.csv": predictions_table[predictions_table["outcome"] == "FN"], "policy_disagreements.csv": pd.concat(disagreements, ignore_index=True), "test_group_metrics.csv": grouped, "actual_interruption_comparison.csv": interruption}
    for name, frame in tables.items():
        write_csv(out / name, frame)
    write_json(out / "bootstrap_intervals.json", uncertainty)
    _exclusions(out, excluded, "test")
    manifest["test_coverage"] = coverage
    manifest["test_legitimate_groups"] = int(cohort.loc[cohort["label"] == 0, "group_id"].nunique())
    resolution = 1 / baseline_metrics["n_negative"]
    warnings = set(manifest.get("warnings", []))
    for target in cfg["fpr_targets"]:
        if target < resolution:
            warnings.add(f"FPR target {target:g} is below empirical resolution {resolution:g} (1/{baseline_metrics['n_negative']} legitimate test requests; {manifest['test_legitimate_groups']} groups).")
        if baseline_metrics["n_negative"] * target < 10:
            warnings.add(f"Only {baseline_metrics['n_negative']} legitimate test requests for target {target:g}; fewer than 10 expected false positives at this rate. Small FPR claims are weakly supported.")
    if (metrics["fp"] == 0).any():
        warnings.add("Zero observed FP can yield a degenerate bootstrap interval; this does not prove population FPR or uncertainty is zero.")
    if data["attack_category"].notna().any() and not cfg["collection_manifest"].get("attack_category_label_source"):
        warnings.add("Attack category analysis omitted: collection_manifest.attack_category_label_source is not declared.")
    manifest["warnings"] = sorted(warnings)
    _complete("evaluate", out, manifest, [*tables, "bootstrap_intervals.json"])
    render_report(out, manifest, quality, locked, metrics, uncertainty, grouped)
    return {"stage": "evaluate", "common_test_n": len(cohort), "policies": len(predictions), "report": str(out / "report.html"), "synthetic": cfg["synthetic"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline, request-level Coraza + CRS threshold evaluation")
    parser.add_argument("command", choices=["validate", "split", "explore", "tune", "evaluate"])
    parser.add_argument("--config", required=True, help="YAML config; paths resolve from this file's directory")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        result = globals()[f"command_{args.command}"](cfg)
        from .utils import canonical_json
        print(canonical_json(result))
        return 0
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"crs-eval: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
