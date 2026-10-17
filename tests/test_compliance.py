"""Unit tests for CIS Foundations compliance scoring."""

from src.analytics.compliance_scorer import ComplianceEvaluator
from src.analytics.iam_analyzer import IAMAnalyzer
from src.telemetry.sample_data import get_sample_iam_hierarchy


def test_compliance_evaluation():
    hierarchy_df = get_sample_iam_hierarchy()
    iam_findings = IAMAnalyzer().audit_hierarchy(hierarchy_df)

    evaluator = ComplianceEvaluator()
    report = evaluator.evaluate(iam_findings=iam_findings, anomaly_count=3)

    assert 0.0 <= report.overall_score <= 100.0
    assert report.passed_controls > 0
    assert report.failed_controls > 0
    assert len(report.controls) == len(report.controls_df)
    assert "Identity & Access Management" in report.domain_scores
    assert "Logging & Monitoring" in report.domain_scores
