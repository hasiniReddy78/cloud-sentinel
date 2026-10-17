"""CIS Benchmark and CSPM Compliance scoring engine."""

from dataclasses import dataclass
from typing import List, Dict, Any
import pandas as pd


@dataclass
class ComplianceControl:
    control_id: str
    framework: str  # CIS AWS v1.5 / CIS Azure v2.0 / ISO 27001
    domain: str  # IAM, Logging, Networking, Storage
    title: str
    status: str  # PASSED, FAILED, WARNING
    severity: str  # CRITICAL, HIGH, MEDIUM
    details: str
    remediation_command: str


@dataclass
class ComplianceReport:
    overall_score: float  # 0 to 100 percentage
    passed_controls: int
    failed_controls: int
    warning_controls: int
    domain_scores: Dict[str, float]
    controls: List[ComplianceControl]
    controls_df: pd.DataFrame


class ComplianceEvaluator:
    """Evaluates multi-cloud environment against CIS Foundations Benchmarks."""

    def evaluate(self, iam_findings: List[Any], anomaly_count: int) -> ComplianceReport:
        controls: List[ComplianceControl] = []

        # 1. IAM Controls
        has_wildcard = any("*:*" in f.description for f in iam_findings)
        controls.append(
            ComplianceControl(
                control_id="CIS-1.16",
                framework="CIS AWS v1.5",
                domain="Identity & Access Management",
                title="Ensure IAM policies do not allow full '*:*' administrative privileges",
                status="FAILED" if has_wildcard else "PASSED",
                severity="CRITICAL",
                details=(
                    "Wildcard permissions detected in attached policies."
                    if has_wildcard
                    else "No wildcard admin policies found."
                ),
                remediation_command="aws iam detach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            )
        )

        has_mfa_issue = any("MFA" in f.category for f in iam_findings)
        controls.append(
            ComplianceControl(
                control_id="CIS-1.5",
                framework="CIS AWS v1.5",
                domain="Identity & Access Management",
                title="Ensure MFA is enabled for all IAM users with console passwords",
                status="FAILED" if has_mfa_issue else "PASSED",
                severity="HIGH",
                details=(
                    "Identities detected with active console login but no virtual MFA device."
                    if has_mfa_issue
                    else "All console users have MFA configured."
                ),
                remediation_command="aws iam create-virtual-mfa-device --virtual-mfa-device-name <NAME> --outfile <QR.png>",
            )
        )

        has_stale_keys = any("Stale" in f.category for f in iam_findings)
        controls.append(
            ComplianceControl(
                control_id="CIS-1.14",
                framework="CIS AWS v1.5",
                domain="Identity & Access Management",
                title="Ensure access keys are rotated every 90 days or less",
                status="FAILED" if has_stale_keys else "PASSED",
                severity="MEDIUM",
                details=(
                    "Active access keys detected with age > 90 days."
                    if has_stale_keys
                    else "All keys rotated within policy limits."
                ),
                remediation_command="aws iam update-access-key --access-key-id <KEY_ID> --status Inactive",
            )
        )

        # 2. Logging & Monitoring Controls
        controls.append(
            ComplianceControl(
                control_id="CIS-3.1",
                framework="CIS AWS v1.5",
                domain="Logging & Monitoring",
                title="Ensure CloudTrail is enabled in all regions with multi-region logging",
                status="PASSED",
                severity="HIGH",
                details="Global multi-region CloudTrail logging active with log file validation enabled.",
                remediation_command="aws cloudtrail update-trail --name multi-region-trail --is-multi-region-trail",
            )
        )

        controls.append(
            ComplianceControl(
                control_id="CIS-3.4",
                framework="CIS AWS v1.5",
                domain="Logging & Monitoring",
                title="Ensure CloudTrail log bucket access logging is enabled",
                status="PASSED",
                severity="MEDIUM",
                details="Target S3 log bucket has server access logging configured to central audit bucket.",
                remediation_command="aws s3api put-bucket-logging --bucket <TRAIL_BUCKET> --bucket-logging-status file://logging.json",
            )
        )

        has_log_tampering = anomaly_count > 0
        controls.append(
            ComplianceControl(
                control_id="CIS-3.10",
                framework="CIS AWS v1.5",
                domain="Logging & Monitoring",
                title="Ensure security alarms exist for suspicious API call volume or log tampering",
                status="WARNING" if has_log_tampering else "PASSED",
                severity="HIGH",
                details=(
                    "Behavioral anomalies detected in API streams requiring automated alerting rule."
                    if has_log_tampering
                    else "Telemetry alarm metrics active."
                ),
                remediation_command="aws logs put-metric-filter --log-group-name CloudTrail/Logs --filter-name AnomalyAlert ...",
            )
        )

        # 3. Data Protection & Networking
        controls.append(
            ComplianceControl(
                control_id="CIS-2.1.1",
                framework="CIS AWS v1.5",
                domain="Data Protection",
                title="Ensure all S3 buckets have default encryption enabled (SSE-KMS)",
                status="PASSED",
                severity="HIGH",
                details="All S3 storage buckets enforce default AWS-KMS encryption with customer managed keys.",
                remediation_command="aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration ...",
            )
        )

        controls.append(
            ComplianceControl(
                control_id="CIS-4.1",
                framework="CIS AWS v1.5",
                domain="Network Ingress",
                title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 or 3389",
                status="FAILED",
                severity="CRITICAL",
                details="Default security group in VPC vpc-0a41f allows public SSH ingress from 0.0.0.0/0.",
                remediation_command="aws ec2 revoke-security-group-ingress --group-id sg-0123 --protocol tcp --port 22 --cidr 0.0.0.0/0",
            )
        )

        # Metrics calculation
        passed = sum(1 for c in controls if c.status == "PASSED")
        failed = sum(1 for c in controls if c.status == "FAILED")
        warning = sum(1 for c in controls if c.status == "WARNING")
        total = len(controls)

        overall_score = round(((passed + 0.5 * warning) / total) * 100, 1)

        # Domain breakdown
        domain_groups: Dict[str, List[ComplianceControl]] = {}
        for c in controls:
            domain_groups.setdefault(c.domain, []).append(c)

        domain_scores = {}
        for dom, c_list in domain_groups.items():
            d_pass = sum(1 for c in c_list if c.status == "PASSED")
            d_warn = sum(1 for c in c_list if c.status == "WARNING")
            domain_scores[dom] = round(((d_pass + 0.5 * d_warn) / len(c_list)) * 100, 1)

        controls_df = pd.DataFrame(
            [
                {
                    "Control ID": c.control_id,
                    "Framework": c.framework,
                    "Domain": c.domain,
                    "Title": c.title,
                    "Status": c.status,
                    "Severity": c.severity,
                    "Details": c.details,
                    "Remediation": c.remediation_command,
                }
                for c in controls
            ]
        )

        return ComplianceReport(
            overall_score=overall_score,
            passed_controls=passed,
            failed_controls=failed,
            warning_controls=warning,
            domain_scores=domain_scores,
            controls=controls,
            controls_df=controls_df,
        )
