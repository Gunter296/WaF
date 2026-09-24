"""Policy semantics, safe serialization, and development-only search contracts."""

import json
import random

import numpy as np
import pandas as pd
import pytest

from crs_eval.policies import (
    canonical_policy, evaluate_policy, instantiate_policy, policy_complexity,
    required_features, validate_policy,
)
from crs_eval.search import _sample_indices, search_policies


def config(features=None, families=None, budget=2000, seed=42, targets=None):
    return {
        "features": features or ["sqli"], "policy_families": families or [],
        "search": {"max_evaluations": budget, "seed": seed},
        "fpr_targets": [0, 0.5, 1] if targets is None else targets,
    }


def test_inclusive_threshold_duplicates_sentinels_and_baseline():
    frame = pd.DataFrame({
        "sqli": [0, 5, 5, 6], "inbound_blocking": [1, 5, 7, 9],
        "inbound_threshold": [1, 6, 7, 10],
    })
    assert evaluate_policy(frame, {"feature": "sqli", "threshold": 5}).tolist() == [False, True, True, True]
    assert evaluate_policy(frame, {"feature": "sqli", "threshold": "all"}).all()
    assert not evaluate_policy(frame, {"feature": "sqli", "threshold": "none"}).any()
    assert evaluate_policy(frame, {"baseline": True}).tolist() == [True, False, True, False]
    assert evaluate_policy(frame, {"baseline": True, "fixed_threshold": 5}).tolist() == [False, True, True, True]
    assert required_features({"baseline": True}) == {"inbound_blocking", "inbound_threshold"}
    assert required_features({"baseline": True, "fixed_threshold": 5}) == {"inbound_blocking"}


def test_and_or_and_disabling_branch():
    frame = pd.DataFrame({"sqli": [0, 5, 5, 0], "xss": [0, 0, 5, 5]})
    template = {"op": "or", "children": [
        {"feature": "sqli", "parameter": "sql"},
        {"op": "and", "children": [
            {"feature": "xss", "parameter": "xss"},
            {"feature": "sqli", "threshold": 5},
        ]},
    ]}
    enabled = instantiate_policy(template, {"sql": "none", "xss": 5})
    assert evaluate_policy(frame, enabled).tolist() == [False, False, True, False]
    disabled = instantiate_policy(template, {"sql": 5, "xss": "none"})
    assert evaluate_policy(frame, disabled).tolist() == [False, True, True, False]
    assert policy_complexity(disabled) == 1
    assert policy_complexity({"op": "or", "children": [enabled, {"constant": True}]}) == 0
    assert policy_complexity({"op": "and", "children": [enabled, {"constant": False}]}) == 0


@pytest.mark.parametrize("policy", [
    "__import__('os').system('echo unsafe')",
    {"feature": "sqli", "threshold": "__import__('os')"},
    {"feature": "sqli", "threshold": float("inf")},
    {"feature": "sqli", "threshold": float("nan")},
    {"feature": "sqli", "threshold": True},
    {"feature": "uri", "threshold": 1},
    {"feature": "sqli", "threshold": 1, "code": "pass"},
    {"constant": "false"},
    {"op": "xor", "children": [{"constant": False}]},
    {"op": "and", "children": []},
    {"baseline": True, "fixed_threshold": float("inf")},
])
def test_rejects_executable_or_ambiguous_policy(policy):
    with pytest.raises(ValueError):
        validate_policy(policy)


def test_missing_never_becomes_zero_and_constant_needs_no_score():
    frame = pd.DataFrame({"sqli": [np.nan, 5]})
    with pytest.raises(ValueError, match="complete cohort"):
        evaluate_policy(frame, {"feature": "sqli", "threshold": 0})
    assert evaluate_policy(frame, {"feature": "sqli", "threshold": "none"}).tolist() == [False, False]
    assert required_features({"feature": "sqli", "threshold": "none"}) == set()
    with pytest.raises(ValueError, match="missing column"):
        evaluate_policy(frame, {"baseline": True})


def test_canonical_json_is_strict_commutative_and_roundtrips():
    children = [{"feature": "sqli", "threshold": "none"}, {"feature": "xss", "threshold": 5.0}]
    expression = {"op": "or", "children": children}
    serialized = canonical_policy(expression)
    assert serialized == canonical_policy({"op": "or", "children": children[::-1]})
    assert serialized == canonical_policy(json.loads(serialized))
    json.dumps(json.loads(serialized), allow_nan=False)
    frame = pd.DataFrame({"xss": [4, 5, 6]})
    np.testing.assert_array_equal(evaluate_policy(frame, expression), evaluate_policy(frame, json.loads(serialized)))


def test_exhaustive_search_uses_only_development_values_and_full_candidates():
    development = pd.DataFrame({"label": [0, 0, 1, 1], "sqli": [0, 1, 2, 2]})
    held_out_test = pd.DataFrame({"label": [0, 1], "sqli": [12345, 99999]})
    candidates, selected, metadata = search_policies(development, config())
    assert held_out_test["sqli"].min() > development["sqli"].max()
    thresholds = [json.loads(value).get("threshold") for value in candidates.expression]
    assert set(value for value in thresholds if isinstance(value, (int, float))) == {0, 1, 2}
    assert {"none", "all"}.issubset(thresholds)
    assert len(candidates) == metadata["evaluations"] == 6
    assert metadata["strategy"] == "exhaustive"
    assert metadata["fraction_explored"] == 1
    assert metadata["global_optimum_certified"] is True
    best = next(policy for policy in selected if policy["selection_scope"] == "global" and policy["fpr_target"] == 0)
    assert best["development_metrics"]["recall"] == 1
    assert best["development_metrics"]["fpr"] == 0
    assert best["only_no_block_feasible"] is False
    json.dumps(selected, allow_nan=False)
    json.dumps(metadata, allow_nan=False)


def test_selection_minimizes_fpr_then_effective_conditions():
    development = pd.DataFrame({"label": [0, 0, 1, 1], "sqli": [0, 1, 2, 3], "xss": [0, 0, 0, 3]})
    families = [{"name": "two_fixed", "expression": {"op": "or", "children": [
        {"feature": "sqli", "threshold": 2}, {"feature": "xss", "threshold": 3},
    ]}}]
    candidates, selected, _ = search_policies(development, config(["sqli", "xss"], families))
    global_winners = [item for item in selected if item["selection_scope"] == "global"]
    assert all(item["family"] == "single_sqli" for item in global_winners)
    assert all(item["development_metrics"]["fpr"] == 0 for item in global_winners)
    assert all(item["complexity"] == 1 for item in global_winners)
    assert candidates[candidates.pareto][["tpr", "fpr"]].drop_duplicates().values.tolist() == [[1.0, 0.0]]


def test_no_block_only_is_explicit_and_metric_none_survives_json():
    development = pd.DataFrame({"label": [0, 0, 1, 1], "sqli": [0, 0, 0, 0]})
    _, selected, _ = search_policies(development, config(targets=[0]))
    assert all(item["only_no_block_feasible"] for item in selected)
    assert all(item["development_metrics"]["precision"] is None for item in selected)
    assert all(item["development_metrics"]["recall"] == 0 for item in selected)
    assert '"precision": null' in json.dumps(selected, allow_nan=False)


def test_random_search_reproducible_budgeted_and_not_global_optimum(monkeypatch):
    import crs_eval.search as search_module

    frame = pd.DataFrame({"label": [0] * 10 + [1] * 10, "sqli": range(20), "xss": range(19, -1, -1)})
    family = {"name": "or_pair", "expression": {"op": "or", "children": [
        {"feature": "sqli", "parameter": "sql"}, {"feature": "xss", "parameter": "xss"},
    ]}}
    settings = config(["sqli", "xss"], [family], budget=30, seed=73)
    original = search_module.evaluate_policy
    count = 0

    def count_calls(data, expression):
        nonlocal count
        count += 1
        return original(data, expression)

    monkeypatch.setattr(search_module, "evaluate_policy", count_calls)
    first = search_policies(frame, settings)
    assert count == first[2]["evaluations"] == 30
    second = search_policies(frame, settings)
    pd.testing.assert_frame_equal(first[0], second[0])
    assert first[1:] == second[1:]
    assert first[2]["global_optimum_certified"] is False
    assert first[2]["fraction_explored"] < 1
    assert first[0].groupby("family").no_block_fallback.sum().eq(1).all()
    changed_seed = config(["sqli", "xss"], [family], budget=30, seed=74)
    assert first[0].expression.tolist() != search_policies(frame, changed_seed)[0].expression.tolist()


def test_huge_cartesian_space_samples_without_materializing():
    indices = _sample_indices(10 ** 100, 30, random.Random(42))
    assert len(set(indices)) == 30
    assert min(indices) >= 0 and max(indices) < 10 ** 100
    frame = pd.DataFrame({"label": [0, 0, 1, 1], "sqli": [0, 1, 2, 3]})
    family = {"name": "huge", "expression": {"op": "or", "children": [
        {"feature": "sqli", "parameter": f"threshold_{i}"} for i in range(40)
    ]}}
    candidates, _, metadata = search_policies(frame, config(families=[family], budget=14))
    assert len(candidates) == 14
    assert metadata["search_space_size_including_fallbacks"] > 10 ** 20
    assert metadata["strategy"] == "random"


def test_search_refuses_unknown_labels_missing_scores_and_insufficient_budget():
    with pytest.raises(ValueError, match="both legitimate"):
        search_policies(pd.DataFrame({"label": [0, 0], "sqli": [1, 2]}), config())
    with pytest.raises(ValueError, match="complete cohort"):
        search_policies(pd.DataFrame({"label": [0, 1], "sqli": [np.nan, 2]}), config())
    frame = pd.DataFrame({"label": [0, 1], "sqli": [0, 2], "xss": [0, 3]})
    with pytest.raises(ValueError, match="no-block fallback"):
        search_policies(frame, config(["sqli", "xss"], budget=1))
