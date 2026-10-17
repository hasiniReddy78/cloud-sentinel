"""Unit tests for IAM privilege analysis and escalation vector detection."""

from src.analytics.iam_analyzer import IAMAnalyzer
from src.telemetry.sample_data import get_sample_iam_hierarchy


def test_iam_analyzer_findings():
    hierarchy_df = get_sample_iam_hierarchy()
    analyzer = IAMAnalyzer()
    findings = analyzer.audit_hierarchy(hierarchy_df)

    assert len(findings) > 0

    # Ensure critical admin wildcard finding is discovered
    categories = [f.category for f in findings]
    assert "Excessive Privilege" in categories

    # Ensure privilege escalation finding is detected
    assert any(f.severity == "CRITICAL" for f in findings)
    assert any("*:*" in f.description for f in findings)

    # Check metrics
    metrics = analyzer.get_summary_metrics(findings)
    assert metrics["total_findings"] == len(findings)
    assert metrics["critical"] > 0
    assert metrics["average_blast_radius"] > 50
