"""Budgeted development-only search over declarative threshold families."""

from __future__ import annotations

import json
import math
import random
from typing import Any

import numpy as np
import pandas as pd

from .metrics import confusion_metrics
from .policies import (
    canonical_policy, evaluate_policy, instantiate_policy, parameter_features,
    policy_complexity, required_features, template_features, validate_policy,
)


def _domains(development: pd.DataFrame, expression: dict) -> dict[str, list[Any]]:
    domains = {}
    for name, features in sorted(parameter_features(expression).items()):
        values = set()
        for feature in sorted(features):
            if feature not in development:
                raise ValueError(f"Search feature {feature!r} is missing")
            array = pd.to_numeric(development[feature], errors="raise").to_numpy(dtype=float, na_value=np.nan)
            if not np.isfinite(array).all():
                raise ValueError(f"Search requires a common complete cohort; {feature!r} has missing/nonfinite values")
            values.update(float(value) for value in np.unique(array))
        domains[name] = ["none", "all", *sorted(values)]
    return domains


def _parameters_at(index: int, domains: dict[str, list[Any]]) -> dict[str, Any]:
    """Decode an integer into a Cartesian product without materializing it."""
    result = {}
    for parameter in reversed(list(domains)):
        options = domains[parameter]
        index, digit = divmod(index, len(options))
        result[parameter] = options[digit]
    return {name: result[name] for name in domains}


def _sample_indices(size: int, count: int, rng: random.Random) -> list[int]:
    if count == size:
        return list(range(size))
    # Floyd's algorithm works for arbitrarily large integer search spaces and
    # costs O(budget), even when the requested fraction is close to one.
    chosen: set[int] = set()
    ordered = []
    for upper in range(size - count, size):
        value = rng.randrange(upper + 1)
        value = upper if value in chosen else value
        chosen.add(value)
        ordered.append(value)
    return ordered


def _pareto(frame: pd.DataFrame) -> pd.Series:
    flags = pd.Series(False, index=frame.index)
    best_previous_tpr = -1.0
    for _, same_fpr in frame.sort_values(["fpr", "tpr"], ascending=[True, False]).groupby("fpr", sort=True):
        maximum = float(same_fpr["tpr"].max())
        if maximum > best_previous_tpr:
            flags.loc[same_fpr.index[same_fpr["tpr"] == maximum]] = True
        best_previous_tpr = max(best_previous_tpr, maximum)
    return flags


def search_policies(development: pd.DataFrame, config: dict) -> tuple[pd.DataFrame, list[dict], dict]:
    """Search only the supplied development rows, returning auditable candidates.

    The budget counts every evaluated family/policy, including one explicit
    no-block fallback per family. Search-space coverage counts parameter
    assignments plus those fallbacks; equivalent prediction vectors are kept.
    Every family gets a fallback before remaining evaluations are distributed
    evenly in configuration order. Random search makes no global-optimum claim.
    """
    if "label" not in development or set(development["label"].dropna().unique()) != {0, 1} or development["label"].isna().any():
        raise ValueError("Development tuning requires verified labels and both legitimate (0) and malicious (1) classes")
    features = config.get("features", [])
    if not isinstance(features, list) or not features or any(not isinstance(f, str) for f in features):
        raise ValueError("features must be a nonempty list of score column names")
    if len(features) != len(set(features)):
        raise ValueError("features must not contain duplicates")
    families = [{"name": f"single_{feature}", "expression": {"feature": feature, "parameter": "threshold"}} for feature in features]
    configured = config.get("policy_families", [])
    if not isinstance(configured, list):
        raise ValueError("policy_families must be a list")
    families.extend(configured)
    names = [f.get("name") for f in families if isinstance(f, dict)]
    if len(names) != len(families) or any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("Each policy family needs a unique nonempty name")
    settings = config.get("search", {})
    budget = settings.get("max_evaluations", 2000)
    seed = settings.get("seed", config.get("seed", 42))
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < len(families):
        raise ValueError(f"max_evaluations must be an integer >= {len(families)} so each family has a no-block fallback")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("Search seed must be an integer")
    raw_targets = config.get("fpr_targets", [0.001, 0.005, 0.01])
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError("fpr_targets must be a nonempty list")
    targets = []
    for value in raw_targets:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("FPR targets must be finite numbers in [0,1]")
        targets.append(float(value))
    targets = sorted(set(targets))

    spaces = []
    for family in families:
        expression = validate_policy(family.get("expression"), allow_parameters=True)
        declared = template_features(expression)
        if declared - set(features):
            raise ValueError(f"Family {family['name']!r} uses scores absent from features: {sorted(declared - set(features))}")
        # Validate fixed-threshold leaves as well as parameter columns before
        # sampling; otherwise missing data could silently affect comparisons.
        for feature in declared:
            if feature not in development or not np.isfinite(pd.to_numeric(development[feature], errors="raise").to_numpy(dtype=float, na_value=np.nan)).all():
                raise ValueError(f"Search requires a common complete cohort for {feature!r}")
        domains = _domains(development, expression)
        size = math.prod(len(options) for options in domains.values())
        spaces.append({"name": family["name"], "expression": expression, "domains": domains, "parameter_space": size, "size": size + 1})

    quotas = [1] * len(spaces)
    remaining = min(budget, sum(space["size"] for space in spaces)) - len(spaces)
    while remaining:
        for index, space in enumerate(spaces):
            if quotas[index] < space["size"]:
                quotas[index] += 1
                remaining -= 1
                if not remaining:
                    break

    rows: list[dict] = []
    metrics_by_candidate: dict[int, dict] = {}
    family_metadata = []
    rng = random.Random(seed)
    labels = development["label"].to_numpy(dtype=int)

    def add_candidate(family: str, expression: dict, parameters: dict, fallback: bool) -> None:
        canonical = canonical_policy(expression)
        metrics = confusion_metrics(labels, evaluate_policy(development, expression))
        metrics_by_candidate[len(rows)] = metrics
        row = {
            "candidate_id": len(rows), "family": family, "expression": canonical,
            "canonical_policy": canonical, "complexity": policy_complexity(expression),
            "parameter_values": json.dumps(parameters, sort_keys=True, allow_nan=False),
            "no_block_fallback": fallback, "split": "development", "cohort": "common_comparison",
        }
        row.update({key: value for key, value in metrics.items() if key != "undefined_reasons"})
        row["undefined_reasons"] = json.dumps(metrics.get("undefined_reasons", {}), sort_keys=True, allow_nan=False)
        rows.append(row)

    for space, quota in zip(spaces, quotas):
        add_candidate(space["name"], {"constant": False}, {}, True)
        indices = _sample_indices(space["parameter_space"], quota - 1, rng)
        for index in indices:
            parameters = _parameters_at(index, space["domains"])
            add_candidate(space["name"], instantiate_policy(space["expression"], parameters), parameters, False)
        family_metadata.append({
            "family": space["name"], "parameter_space_size": space["parameter_space"],
            "search_space_size_including_fallback": space["size"], "evaluations": quota,
            "fraction_explored": quota / space["size"],
            "strategy": "exhaustive" if quota == space["size"] else "random",
            "global_optimum_certified_for_family": quota == space["size"],
            "candidate_values": space["domains"],
        })

    candidates = pd.DataFrame(rows)
    candidates["pareto"] = _pareto(candidates)
    candidates["pareto_family"] = False
    for _, group in candidates.groupby("family", sort=False):
        candidates.loc[group.index, "pareto_family"] = _pareto(group)

    selected = []

    def select(group: pd.DataFrame, target: float, scope: str) -> None:
        feasible = group[group["fpr"] <= target]
        ordered = feasible.sort_values(["tpr", "fpr", "complexity", "canonical_policy", "family"], ascending=[False, True, True, True, True], kind="stable")
        winner = ordered.iloc[0]
        expression = json.loads(winner["expression"])
        target_name = format(target, ".12g").replace(".", "p").replace("-", "m")
        metrics = dict(metrics_by_candidate[int(winner["candidate_id"])])
        selected.append({
            "name": f"{winner['family'] if scope == 'family' else 'best'}__fpr_{target_name}",
            "family": str(winner["family"]), "selection_scope": scope,
            "fpr_target": target, "expression": expression,
            "required_features": sorted(required_features(expression)), "development_metrics": metrics,
            "complexity": int(winner["complexity"]), "candidate_id": int(winner["candidate_id"]),
            "only_no_block_feasible": bool(((feasible["tp"] + feasible["fp"]) == 0).all()),
        })

    for target in targets:
        for _, group in candidates.groupby("family", sort=False):
            select(group, target, "family")
        select(candidates, target, "global")
    total_space = sum(space["size"] for space in spaces)
    metadata = {
        "split": "development", "seed": seed, "max_evaluations": budget,
        "evaluations": len(candidates), "search_space_size_including_fallbacks": total_space,
        "fraction_explored": len(candidates) / total_space,
        "strategy": "exhaustive" if len(candidates) == total_space else "random",
        "global_optimum_certified": len(candidates) == total_space,
        "budget_allocation": "one no-block fallback per family, then round-robin in configuration order",
        "tie_break": ["maximum development TPR", "minimum development FPR", "minimum effective conditions", "canonical JSON lexicographic order", "family name"],
        "search_space_unit": "parameter assignments plus one no-block fallback per family; equivalent predictions retained",
        "families": family_metadata,
    }
    return candidates, selected, metadata
