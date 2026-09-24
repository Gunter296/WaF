"""Hand-calculated metrics and leakage-sensitive development analysis checks."""

import json

import numpy as np
import pandas as pd
import pytest

from crs_eval.metrics import common_cohort, confusion_metrics, paired_group_bootstrap, require_two_classes
from crs_eval.roc import analyze_scores


def test_confusion_metrics_hand_calculated():
    result = confusion_metrics([0, 0, 0, 0, 1, 1, 1], [1, 0, 0, 0, 1, 1, 0])
    assert {key: result[key] for key in ("tp", "fp", "tn", "fn")} == {"tp": 2, "fp": 1, "tn": 3, "fn": 1}
    assert result["n"] == 7
    assert result["n_positive"] == 3
    assert result["n_negative"] == 4
    assert result["recall"] == result["tpr"] == pytest.approx(2 / 3)
    assert result["precision"] == pytest.approx(2 / 3)
    assert result["fpr"] == 0.25
    assert result["specificity"] == 0.75
    assert result["f1"] == pytest.approx(2 / 3)
    assert result["prevalence"] == pytest.approx(3 / 7)
    assert result["empirical_fpr_resolution"] == 0.25
    assert result["undefined_reasons"] == {}


def test_zero_denominators_are_null_with_reasons_not_silent_zero():
    empty = confusion_metrics([], [])
    for metric in ("recall", "tpr", "fpr", "precision", "specificity", "f1", "prevalence"):
        assert empty[metric] is None
        assert metric in empty["undefined_reasons"]
    no_actual_or_predicted_positive = confusion_metrics([0, 0], [0, 0])
    assert no_actual_or_predicted_positive["f1"] is None
    assert no_actual_or_predicted_positive["precision"] is None
    no_predicted_positive = confusion_metrics([0, 1], [0, 0])
    assert no_predicted_positive["recall"] == 0
    assert no_predicted_positive["f1"] == 0  # 2TP + FP + FN = 1, not an undefined ratio.
    assert no_predicted_positive["precision"] is None
    assert confusion_metrics([1, 1], [1, 0])["fpr"] is None
    json.dumps(empty, allow_nan=False)


@pytest.mark.parametrize("labels,predictions", [([0, None], [0, 1]), ([0, 2], [0, 1]), ([0, 1], [0]), ([0], [np.nan])])
def test_metrics_reject_misaligned_unknown_or_nonbinary_inputs(labels, predictions):
    with pytest.raises(ValueError):
        confusion_metrics(labels, predictions)


def test_common_cohort_preserves_missing_and_reports_class_denominators():
    frame = pd.DataFrame({
        "label": [0, 0, 1, 1, None], "score_a": [0, np.nan, 8, 9, 2],
        "score_b": [0, 1, 4, np.nan, 2], "summary_status": ["partial"] * 5,
    })
    cohort, coverage, excluded = common_cohort(frame, ["score_a", "score_b"])
    assert cohort.index.tolist() == [0, 2]
    assert cohort["score_a"].tolist() == [0, 8]
    assert len(excluded) == 3
    assert np.isnan(frame.loc[1, "score_a"])
    assert np.isnan(excluded.loc[1, "score_a"])
    assert coverage["n_unknown"] == 1
    assert coverage["coverage"] == 2 / 5
    assert coverage["by_class"]["legitimate"] == {"n_total": 2, "n_included": 1, "n_excluded": 1, "coverage": 0.5}
    assert coverage["by_class"]["malicious"]["coverage"] == 0.5
    assert "missing_or_invalid_score:score_a" in excluded.loc[1, "exclusion_reason"]
    assert "unknown_label" in excluded.loc[4, "exclusion_reason"]
    assert cohort["summary_status"].eq("partial").all()


def test_common_cohort_excludes_infinite_scores_instead_of_calling_them_valid():
    cohort, coverage, excluded = common_cohort(pd.DataFrame({"label": [0, 1], "x": [np.inf, 2]}), ["x"])
    assert cohort.index.tolist() == [1]
    assert coverage["by_class"]["legitimate"]["coverage"] == 0
    assert len(excluded) == 1


def test_source_errors_and_timeouts_are_audited_not_scored_as_bypass_or_block():
    frame = pd.DataFrame({
        "label": [0, 1, 0, 1], "score": [0, 9, 2, 8],
        "request_error": [None, "tool failed", None, None],
        "timeout": [False, False, True, False],
    })
    cohort, coverage, excluded = common_cohort(frame, ["score"])
    assert cohort.index.tolist() == [0, 3]
    assert coverage["excluded_reason_counts"]["source_request_error"] == 1
    assert coverage["excluded_reason_counts"]["source_timeout"] == 1
    assert "source_request_error" in excluded.loc[1, "exclusion_reason"]
    assert "source_timeout" in excluded.loc[2, "exclusion_reason"]
    summary, candidates, curves = analyze_scores(frame, ["score"], [0.1])
    assert summary.iloc[0]["n"] == 2
    assert candidates["n"].eq(2).all()


def test_two_class_error_is_actionable():
    with pytest.raises(ValueError, match="both legitimate.*malicious.*group split"):
        require_two_classes([1, 1], "Tuning")


def test_roc_keeps_tied_thresholds_exact_ge_and_json_safe_sentinels():
    frame = pd.DataFrame({"label": [0, 0, 1, 1], "score": [0, 1, 1, 2]})
    metrics, candidates, curves = analyze_scores(frame, ["score"], [0, 0.5, 1])
    assert len(candidates) == 5  # Every distinct numeric value plus all/none.
    one = candidates.loc[candidates["threshold"].eq(1)].iloc[0]
    assert (one["tp"], one["fp"], one["tn"], one["fn"]) == (2, 1, 1, 0)
    assert json.loads(one["selected_for_targets"]) == [0.5, 1.0]
    two = candidates.loc[candidates["threshold"].eq(2)].iloc[0]
    assert json.loads(two["selected_for_targets"]) == [0.0]
    all_row = candidates.loc[candidates["threshold_kind"].eq("all")].iloc[0]
    none_row = candidates.loc[candidates["threshold_kind"].eq("none")].iloc[0]
    assert all_row["threshold"] is None and none_row["threshold"] is None
    assert (all_row["tp"], all_row["fp"]) == (2, 2)
    assert (none_row["tp"], none_row["fp"]) == (0, 0)
    assert len(curves["score"]["fpr"]) == 4
    assert metrics.iloc[0]["roc_auc"] == pytest.approx(0.875)
    assert metrics.iloc[0]["average_precision"] == pytest.approx(5 / 6)
    json.dumps(curves, allow_nan=False)
    json.dumps(candidates[["threshold_kind", "threshold"]].to_dict("records"), allow_nan=False)


def test_roc_no_intermediate_thresholds_are_discarded():
    _, candidates, curves = analyze_scores(pd.DataFrame({"label": [0, 0, 0, 1, 1, 1], "score": range(6)}), ["score"], [0])
    assert len(candidates) == 8
    assert len(curves["score"]["fpr"]) == 7


def test_analysis_uses_only_development_thresholds_and_each_available_cohort():
    development = pd.DataFrame({"label": [0, 0, 1, 1], "a": [0, 1, 2, 3], "b": [0, np.nan, 2, np.nan]})
    untouched_test = pd.DataFrame({"label": [0, 1], "a": [999, 1000], "b": [900, 1000]})
    metrics, candidates, _ = analyze_scores(development, ["a", "b"], [0])
    assert set(candidates.loc[candidates["threshold_kind"].eq("numeric"), "threshold"]) == {0, 1, 2, 3}
    assert untouched_test["a"].min() == 999
    assert metrics.set_index("feature")["n"].to_dict() == {"a": 4, "b": 2}
    assert metrics["cohort"].tolist() == ["feature_available:a", "feature_available:b"]
    assert metrics.set_index("feature").loc["b", "legitimate_coverage"] == 0.5


def test_constant_all_missing_and_single_class_scores_have_explicit_status():
    frame = pd.DataFrame({"label": [0, 0, 1, 1], "constant": [5] * 4,
                          "missing": [np.nan] * 4, "only_positive": [np.nan, np.nan, 1, 2]})
    metrics, candidates, curves = analyze_scores(frame, ["constant", "missing", "only_positive"], [0, 1])
    scores = metrics.set_index("feature")
    assert scores.loc["constant", "status"] == "constant"
    assert scores.loc["constant", "roc_auc"] == 0.5
    assert scores.loc["constant", "average_precision"] == 0.5
    assert scores.loc["missing", "status"] == scores.loc["only_positive", "status"] == "excluded"
    assert "missing" in scores.loc["missing", "reason"]
    assert "lacks legitimate" in scores.loc["only_positive", "reason"]
    assert set(curves) == {"constant"}
    selected = json.loads(scores.loc["constant", "selected_thresholds"])
    assert selected[0]["threshold_kind"] == "none"
    assert selected[0]["only_feasible_by_blocking_none"] is True
    assert selected[1]["threshold_kind"] == "numeric"  # Deterministic tie with all sentinel.
    none = candidates.loc[candidates["threshold_kind"].eq("none")].iloc[0]
    assert json.loads(none["none_only_for_targets"]) == [0.0]


def test_entire_one_class_development_stops_roc():
    with pytest.raises(ValueError, match="requires both"):
        analyze_scores(pd.DataFrame({"label": [1, 1], "score": [1, 2]}), ["score"], [0.01])


def test_group_bootstrap_is_paired_reproducible_and_counts_whole_groups():
    labels = [0, 1, 0, 1]
    predictions = {"base": [0, 1, 0, 0], "copy": [0, 1, 0, 0], "policy": [0, 1, 1, 1]}
    result = paired_group_bootstrap(labels, predictions, ["a", "a", "b", "b"], "base", 200, 7)
    assert result == paired_group_bootstrap(labels, predictions, ["a", "a", "b", "b"], "base", 200, 7)
    assert result["requested_iterations"] == result["valid_iterations"] == 200
    assert result["n_groups"] == result["n_legitimate_groups"] == 2
    for delta in ("delta_recall", "delta_fpr"):
        assert result["policies"]["copy"][delta]["lower"] == 0
        assert result["policies"]["copy"][delta]["upper"] == 0
    assert result["policies"]["policy"]["delta_recall"] == result["policies"]["policy"]["delta_fpr"]
    assert result["policies"]["policy"]["delta_recall"]["estimate"] == 0.5
    assert "does not establish" in result["policies"]["base"]["zero_fp_limitation"]
    assert result["policies"]["policy"]["zero_fp_limitation"] is None
    json.dumps(result, allow_nan=False)


def test_bootstrap_skips_single_class_replicates_and_undefined_precision():
    result = paired_group_bootstrap([0, 0, 1, 1], {"base": [0, 0, 0, 0]}, ["leg", "leg", "mal", "mal"], "base", 100, 5)
    assert 0 < result["valid_iterations"] < 100
    assert result["valid_iterations"] + result["skipped_iterations"] == 100
    precision = result["policies"]["base"]["metrics"]["precision"]
    assert precision["estimate"] is precision["lower"] is precision["upper"] is None
    assert precision["valid_iterations"] == 0
    assert result["policies"]["base"]["metrics"]["f1"]["estimate"] == 0


def test_disabled_bootstrap_returns_null_intervals_without_fake_replicates():
    result = paired_group_bootstrap([0, 1], {"base": [0, 1]}, ["a", "b"], "base", 0, 1)
    assert result["valid_iterations"] == 0
    assert result["policies"]["base"]["metrics"]["recall"]["lower"] is None


@pytest.mark.parametrize("groups", [["a"], [None, "b"], ["", "b"]])
def test_bootstrap_requires_aligned_nonmissing_groups(groups):
    with pytest.raises(ValueError, match="group"):
        paired_group_bootstrap([0, 1], {"base": [0, 1]}, groups, "base", 10, 1)
