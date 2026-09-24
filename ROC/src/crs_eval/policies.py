"""Safe, declarative inbound threshold policies.

The AST has score leaves, AND/OR nodes, boolean constants and the explicitly
named CRS baseline.  Nothing in this module interprets executable strings.
``all`` and ``none`` are JSON-safe threshold sentinels.
"""

from __future__ import annotations

import json
import math
from numbers import Real
from typing import Any, Mapping

import numpy as np
import pandas as pd


Policy = dict[str, Any]
SENTINELS = ("all", "none")
_FORBIDDEN_FEATURES = {
    "label", "request_id", "run_id", "timestamp", "uri", "method",
    "http_status", "interrupted", "dataset_source", "template_id", "cve_id",
    "group_id", "attack_category", "configuration_id", "summary_status",
}


def _finite_number(value: Any, field: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{field} must be a finite number, not {value!r}")
    if not math.isfinite(float(value)):
        raise ValueError(f"{field} must be finite; use 'all'/'none' sentinels")
    return int(value) if isinstance(value, (int, np.integer)) else float(value)


def validate_policy(policy: Mapping[str, Any], *, allow_parameters: bool = False) -> Policy:
    """Return a validated JSON-compatible copy; reject ambiguous/unknown keys."""
    nodes = 0

    def visit(node: Any, depth: int = 0) -> Policy:
        nonlocal nodes
        nodes += 1
        if depth > 64 or nodes > 10000:
            raise ValueError("Policy AST is too large or deeply nested")
        if not isinstance(node, Mapping):
            raise ValueError("Each policy node must be an object")
        keys = set(node)
        if keys == {"constant"}:
            if not isinstance(node["constant"], bool):
                raise ValueError("Policy constant must be a boolean")
            return {"constant": node["constant"]}
        if "baseline" in keys:
            if keys - {"baseline", "fixed_threshold"} or node["baseline"] is not True:
                raise ValueError("Baseline node requires baseline=true and optional fixed_threshold")
            threshold = node.get("fixed_threshold")
            if threshold is not None:
                threshold = _finite_number(threshold, "fixed_threshold")
            return {"baseline": True, "fixed_threshold": threshold}
        if "op" in keys:
            if keys != {"op", "children"} or node["op"] not in ("and", "or"):
                raise ValueError("Operator nodes require op='and'/'or' and children")
            if not isinstance(node["children"], list) or not node["children"]:
                raise ValueError("AND/OR children must be a nonempty list")
            return {"op": node["op"], "children": [visit(c, depth + 1) for c in node["children"]]}
        if "feature" in keys:
            feature = node["feature"]
            if not isinstance(feature, str) or not feature:
                raise ValueError("Policy feature must be a nonempty column name")
            if feature.lower() in _FORBIDDEN_FEATURES:
                raise ValueError(f"Metadata {feature!r} cannot be a decision feature")
            if keys == {"feature", "threshold"}:
                threshold = node["threshold"]
                if not isinstance(threshold, str) or threshold not in SENTINELS:
                    threshold = _finite_number(threshold, "threshold")
                return {"feature": feature, "threshold": threshold}
            if allow_parameters and keys == {"feature", "parameter"}:
                parameter = node["parameter"]
                if not isinstance(parameter, str) or not parameter:
                    raise ValueError("Parameter must be a nonempty name")
                return {"feature": feature, "parameter": parameter}
            raise ValueError("Score leaves require exactly feature and threshold (or a template parameter)")
        raise ValueError("Unknown policy node; executable policy strings are unsupported")

    return visit(policy)


def _canonical_validated(node: Policy) -> str:
    if "op" in node:
        node = {"op": node["op"], "children": [
            json.loads(child) for child in sorted(_canonical_validated(c) for c in node["children"])
        ]}
    return json.dumps(node, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_policy(policy: Mapping[str, Any]) -> str:
    """Stable strict JSON, including a deterministic order for AND/OR children."""
    return _canonical_validated(validate_policy(policy))


def required_features(policy: Mapping[str, Any]) -> set[str]:
    """Columns actually read by a locked policy (sentinels need no score)."""
    node = validate_policy(policy)

    def visit(item: Policy) -> set[str]:
        if "baseline" in item:
            return {"inbound_blocking"} | ({"inbound_threshold"} if item["fixed_threshold"] is None else set())
        if "feature" in item:
            return {item["feature"]} if item["threshold"] not in SENTINELS else set()
        if "op" in item:
            return set().union(*(visit(c) for c in item["children"]))
        return set()

    return visit(node)


def template_features(policy: Mapping[str, Any]) -> set[str]:
    """All declared score columns, including disabled/template leaves."""
    node = validate_policy(policy, allow_parameters=True)
    if "feature" in node:
        return {node["feature"]}
    if "op" in node:
        return set().union(*(template_features(c) for c in node["children"]))
    if "baseline" in node:
        return required_features(node)
    return set()


def parameter_features(policy: Mapping[str, Any]) -> dict[str, set[str]]:
    node = validate_policy(policy, allow_parameters=True)
    result: dict[str, set[str]] = {}

    def visit(item: Policy) -> None:
        if "parameter" in item:
            result.setdefault(item["parameter"], set()).add(item["feature"])
        for child in item.get("children", []):
            visit(child)

    visit(node)
    return result


def instantiate_policy(template: Mapping[str, Any], parameters: Mapping[str, Any]) -> Policy:
    node = validate_policy(template, allow_parameters=True)
    expected = set(parameter_features(node))
    if set(parameters) != expected:
        raise ValueError(f"Policy parameters must be exactly {sorted(expected)}")

    def visit(item: Policy) -> Policy:
        if "parameter" in item:
            return {"feature": item["feature"], "threshold": parameters[item["parameter"]]}
        if "op" in item:
            return {"op": item["op"], "children": [visit(c) for c in item["children"]]}
        return item

    return validate_policy(visit(node))


def policy_complexity(policy: Mapping[str, Any]) -> int:
    """Number of effective score conditions after boolean constant folding."""
    node = validate_policy(policy)

    def visit(item: Policy) -> tuple[bool | None, int]:
        if "constant" in item:
            return item["constant"], 0
        if "feature" in item:
            if item["threshold"] in SENTINELS:
                return item["threshold"] == "all", 0
            return None, 1
        if "baseline" in item:
            return None, 1
        children = [visit(c) for c in item["children"]]
        absorbing = item["op"] == "or"
        if any(constant is absorbing for constant, _ in children):
            return absorbing, 0
        active = [complexity for constant, complexity in children if constant is None]
        return (None, sum(active)) if active else (not absorbing, 0)

    return visit(node)[1]


def evaluate_policy(data: pd.DataFrame, policy: Mapping[str, Any]) -> np.ndarray:
    """Predict blocking with inclusive ``>=``; refuse missing/nonfinite inputs.

    Callers must establish and report a common complete-case comparison cohort.
    Missing scores are never imputed, even inside an otherwise true OR branch.
    """
    node = validate_policy(policy)
    values: dict[str, np.ndarray] = {}
    for feature in sorted(required_features(node)):
        if feature not in data.columns:
            raise ValueError(f"Policy requires missing column {feature!r}")
        try:
            array = pd.to_numeric(data[feature], errors="raise").to_numpy(dtype=float, na_value=np.nan)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Policy score {feature!r} must be numeric") from exc
        if not np.isfinite(array).all():
            raise ValueError(f"Policy score {feature!r} contains missing/nonfinite values; establish a complete cohort first")
        values[feature] = array

    def visit(item: Policy) -> np.ndarray:
        if "constant" in item:
            return np.full(len(data), item["constant"], dtype=bool)
        if "baseline" in item:
            threshold = item["fixed_threshold"]
            return values["inbound_blocking"] >= (values["inbound_threshold"] if threshold is None else threshold)
        if "feature" in item:
            threshold = item["threshold"]
            if threshold in SENTINELS:
                return np.full(len(data), threshold == "all", dtype=bool)
            return values[item["feature"]] >= threshold
        operation = np.logical_and if item["op"] == "and" else np.logical_or
        children = [visit(c) for c in item["children"]]
        return operation.reduce(children)

    return visit(node)
