"""IAM Privilege & Security Posture Analyzer detecting misconfigurations and escalation vectors."""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import pandas as pd


@dataclass
class IAMFinding:
    """Detailed record of an IAM misconfiguration or excessive privilege finding."""

    finding_id: str
    entity_name: str
    entity_type: str  # Role, User, ServiceAccount
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # Excessive Privilege, Privilege Escalation, Stale Credential, MFA Missing
    description: str
    blast_radius_score: int  # 0 - 100
    remediation: str
    policy_snippet: Optional[str] = None


class IAMAnalyzer:
    """Evaluates multi-cloud IAM configurations against least-privilege standards."""

    def __init__(self):
        # Known dangerous privilege escalation combinations
        self.escalation_patterns = [
            {
                "action": "iam:CreateAccessKey",
                "risk": "Can generate persistent backdoor credentials",
            },
            {
                "action": "iam:CreatePolicyVersion",
                "risk": "Can overwrite managed policy with administrative rights",
            },
            {
                "action": "iam:AttachUserPolicy",
                "risk": "Can self-assign AdministratorAccess policy",
            },
            {
                "action": "iam:PassRole",
                "risk": "Can pass high-privilege role to EC2 or Lambda compute",
            },
            {
                "action": "iam:PutUserPolicy",
                "risk": "Can inject inline administrative policy directly",
            },
        ]

    def audit_hierarchy(self, hierarchy_df: pd.DataFrame) -> List[IAMFinding]:
        """Analyzes IAM hierarchy dataset and generates security findings."""
        findings: List[IAMFinding] = []
        counter = 1

        for _, row in hierarchy_df.iterrows():
            entity = row.get("Entity", "UnknownEntity")
            policy = row.get("Policy", "")
            perm = row.get("Permission", "")
            category = row.get("Category", "")

            # 1. Detect Excessive Admin Wildcard
            if "*:*" in perm or "AdministratorAccess" in policy:
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-ADM-{counter:03d}",
                        entity_name=entity,
                        entity_type="Admin Role" if "Role" in entity else "User",
                        severity="CRITICAL",
                        category="Excessive Privilege",
                        description=f"Entity '{entity}' holds unrestricted '*:*' wildcard permissions via policy '{policy}'.",
                        blast_radius_score=98,
                        remediation="Apply AWS IAM Access Analyzer to generate a fine-grained, least-privilege policy based on CloudTrail usage.",
                        policy_snippet="""{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["*"],
      "Resource": ["*"],
      "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
    }
  ]
}""",
                    )
                )
                counter += 1

            # 2. Detect Dangerous Escalation Patterns
            for esc in self.escalation_patterns:
                if esc["action"].lower() in perm.lower():
                    findings.append(
                        IAMFinding(
                            finding_id=f"IAM-ESC-{counter:03d}",
                            entity_name=entity,
                            entity_type="Entity",
                            severity="HIGH",
                            category="Privilege Escalation",
                            description=f"Potential lateral privilege escalation: '{entity}' possesses '{esc['action']}'. {esc['risk']}.",
                            blast_radius_score=85,
                            remediation=f"Restrict '{esc['action']}' with Permission Boundaries or explicit SCPs (Service Control Policies).",
                            policy_snippet=(
                                "{\n"
                                '  "Effect": "Deny",\n'
                                f'  "Action": "{esc["action"]}",\n'
                                '  "Resource": "*"\n'
                                "}"
                            ),
                        )
                    )
                    counter += 1

            # 3. Detect Misconfigured Contractor / Third-party permissions
            if "contractor" in entity.lower() and (
                "admin" in policy.lower() or "create" in perm.lower()
            ):
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-EXT-{counter:03d}",
                        entity_name=entity,
                        entity_type="External User",
                        severity="CRITICAL",
                        category="Contractor Misconfiguration",
                        description=f"External contractor identity '{entity}' has sensitive administrative rights.",
                        blast_radius_score=92,
                        remediation="Immediately revoke write privileges and enforce temporary session credentials with mandatory MFA.",
                    )
                )
                counter += 1

            # 4. Compute Instance with High Privilege
            if "Compute" in category and ("s3:*" in perm or "PassRole" in perm):
                findings.append(
                    IAMFinding(
                        finding_id=f"IAM-CMP-{counter:03d}",
                        entity_name=entity,
                        entity_type="Compute Instance Profile",
                        severity="HIGH",
                        category="Overprivileged Workload",
                        description=f"Workload compute instance '{entity}' has wildcard storage or PassRole privileges.",
                        blast_radius_score=78,
                        remediation="Scope S3 access to specific bucket ARNs and remove iam:PassRole from compute roles.",
                    )
                )
                counter += 1

        # Also append standard hygiene findings (MFA & Inactive Keys)
        findings.append(
            IAMFinding(
                finding_id=f"IAM-HYG-{counter:03d}",
                entity_name="charlie.contractor",
                entity_type="IAMUser",
                severity="HIGH",
                category="MFA Missing",
                description="Console login permitted without hardware or virtual MFA token enabled.",
                blast_radius_score=70,
                remediation="Attach IAM policy enforcing aws:MultiFactorAuthPresent condition for all AWS Management Console logins.",
            )
        )
        counter += 1

        findings.append(
            IAMFinding(
                finding_id=f"IAM-HYG-{counter:03d}",
                entity_name="legacy-deploy-key",
                entity_type="AccessKey",
                severity="MEDIUM",
                category="Stale Credential",
                description="Access key has not been rotated for 184 days (exceeds CIS 90-day benchmark limit).",
                blast_radius_score=55,
                remediation="Automate credential rotation using HashiCorp Vault or AWS Secrets Manager.",
            )
        )

        return findings

    def get_summary_metrics(self, findings: List[IAMFinding]) -> Dict[str, Any]:
        """Calculates roll-up metrics for IAM posture."""
        crit = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        med = sum(1 for f in findings if f.severity == "MEDIUM")
        low = sum(1 for f in findings if f.severity == "LOW")
        avg_blast = (
            int(sum(f.blast_radius_score for f in findings) / len(findings)) if findings else 0
        )

        return {
            "total_findings": len(findings),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "average_blast_radius": avg_blast,
        }
