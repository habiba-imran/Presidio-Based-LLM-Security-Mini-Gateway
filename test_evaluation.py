import os

from evaluation.run_evaluation import run_all_evaluations


REQUIRED_FILES = [
    "scenario_level_evaluation.csv",
    "presidio_customization_validation.csv",
    "threshold_calibration.csv",
    "latency_summary.csv",
    "bonus_llm_before_after.csv",
    "performance_summary_metrics.json",
]


def test_evaluation_artifacts_generation():
    run_all_evaluations()
    for file_name in REQUIRED_FILES:
        path = os.path.join("evaluation", "results", file_name)
        assert os.path.exists(path)
