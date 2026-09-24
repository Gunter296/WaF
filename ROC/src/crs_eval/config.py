"""Configuration paths are relative to the YAML file, never the working directory."""
from __future__ import annotations

import copy
import math
from pathlib import Path

import yaml

from .utils import object_hash

DEFAULT_FEATURES = ["inbound_blocking", "inbound_detection", "pl1", "pl2", "pl3", "pl4", "sqli", "xss", "rce", "lfi", "rfi", "phpi", "http", "sess"]
FORBIDDEN_FEATURES = {"uri", "request_id", "run_id", "label", "http_status", "interrupted", "cve_id", "template_id", "dataset_source", "group_id", "configuration_id", "attack_category", "timestamp", "method", "summary_status", "inbound_threshold", "request_error", "timeout"}


def load_config(path):
    path = Path(path).resolve()
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        raise ValueError("Configuration must be a YAML mapping")
    cfg = copy.deepcopy(cfg)
    cfg.setdefault("features", DEFAULT_FEATURES.copy())
    cfg.setdefault("field_mapping", {})
    cfg.setdefault("score_fields", [])
    cfg.setdefault("feature_metadata", {})
    cfg.setdefault("derived_features", {})
    cfg.setdefault("duplicate_handling", "error")
    cfg.setdefault("grouping", {"field": "group_id", "allow_request_fallback": False})
    cfg.setdefault("split", {})
    cfg["split"].setdefault("test_size", 0.3)
    cfg["split"].setdefault("seed", 42)
    cfg.setdefault("search", {})
    cfg["search"].setdefault("max_evaluations", 2000)
    cfg["search"].setdefault("seed", cfg["split"]["seed"])
    cfg.setdefault("bootstrap", {})
    cfg["bootstrap"].setdefault("iterations", 1000)
    cfg["bootstrap"].setdefault("seed", cfg["split"]["seed"])
    cfg["bootstrap"].setdefault("confidence", 0.95)
    cfg.setdefault("fpr_targets", [0.001, 0.005, 0.01])
    cfg.setdefault("baseline", {})
    cfg.setdefault("export", {"include_uri": False})
    cfg.setdefault("collection_manifest", {})
    cfg.setdefault("policy_families", [])
    cfg.setdefault("synthetic", False)
    cfg.setdefault("uri_cve_prefix", True)
    if not isinstance(cfg["uri_cve_prefix"], bool):
        raise ValueError("uri_cve_prefix must be true or false")
    source = cfg.get("input", {})
    paths = source.get("paths", [])
    if not isinstance(paths, list) or not paths:
        raise ValueError("input.paths must be a nonempty list")
    source["paths"] = [str((path.parent / p).resolve()) for p in paths]
    if source.get("format") not in ("csv", "jsonl"):
        raise ValueError("input.format must be csv or jsonl")
    if cfg.get("labels"):
        cfg["labels"]["path"] = str((path.parent / cfg["labels"]["path"]).resolve())
    if cfg.get("replay"):
        cfg["replay"]["path"] = str((path.parent / cfg["replay"]["path"]).resolve())
    cfg["output_path"] = str((path.parent / cfg.get("output_path", "../outputs/experiment")).resolve())
    if not 0 < cfg["split"]["test_size"] < 1:
        raise ValueError("split.test_size must be between zero and one")
    if not cfg["fpr_targets"] or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not 0 <= v <= 1 for v in cfg["fpr_targets"]):
        raise ValueError("fpr_targets must contain finite values in [0, 1]")
    for settings, key in ((cfg["search"], "max_evaluations"), (cfg["bootstrap"], "iterations")):
        if isinstance(settings[key], bool) or not isinstance(settings[key], int) or settings[key] < 1:
            raise ValueError(f"{key} must be a positive integer")
    if not 0 < cfg["bootstrap"]["confidence"] < 1:
        raise ValueError("bootstrap.confidence must be between zero and one")
    fixed = cfg["baseline"].get("fixed_threshold")
    if fixed is not None and (isinstance(fixed, bool) or not isinstance(fixed, (int, float)) or not math.isfinite(fixed)):
        raise ValueError("baseline.fixed_threshold must be finite")
    if not isinstance(cfg["features"], list) or not cfg["features"] or len(set(cfg["features"])) != len(cfg["features"]):
        raise ValueError("features must be a nonempty list of unique score names")
    base = set(DEFAULT_FEATURES) | set(cfg["score_fields"])
    for name, definition in cfg["derived_features"].items():
        if name in base or name in FORBIDDEN_FEATURES:
            raise ValueError(f"Derived feature must have a new score name: {name}")
        if not isinstance(definition, dict) or set(definition) != {"sum"} or not definition["sum"] or not set(definition["sum"]) <= base:
            raise ValueError(f"Derived feature {name} supports an explicit sum of base scores only")
    allowed = base | set(cfg["derived_features"])
    used = set(cfg["features"])
    def collect(node):
        if not isinstance(node, dict):
            raise ValueError("Policy expression must be a mapping")
        if "feature" in node:
            used.add(node["feature"])
        for child in node.get("children", []):
            collect(child)
    for family in cfg["policy_families"]:
        collect(family["expression"])
    used.update(f for definition in cfg["derived_features"].values() for f in definition["sum"])
    if (used & FORBIDDEN_FEATURES) or not used <= allowed:
        raise ValueError(f"Only declared inbound scores may decide policy: {sorted((used & FORBIDDEN_FEATURES) | (used - allowed))}")
    for name in used - set(DEFAULT_FEATURES) - set(cfg["derived_features"]):
        metadata = cfg["feature_metadata"].get(name, {})
        if metadata.get("phase") != "inbound" or not metadata.get("meaning"):
            raise ValueError(f"Custom decision score {name} needs feature_metadata with phase: inbound and meaning")
    for name in used:
        phase = cfg["feature_metadata"].get(name, {}).get("phase", "inbound")
        if phase != "inbound":
            raise ValueError(f"Response/outbound score cannot be used in an inbound policy: {name}")
    cfg["_config_path"] = str(path)
    cfg["_config_hash"] = object_hash({k: v for k, v in cfg.items() if not k.startswith("_") and k != "output_path"})
    return cfg
