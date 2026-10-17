from datetime import datetime, timedelta, timezone
import pandas as pd
from typing import Dict, Any, List


def get_sample_telemetry(num_records: int = 250) -> pd.DataFrame:
    """Generates a rich, realistic baseline with injected high-severity security incidents."""
    base_time = datetime.now(timezone.utc) - timedelta(days=2)
    records: List[Dict[str, Any]] = []

    # 1. Normal DevSecOps / SRE Baseline activity
    normal_users = ["alice.sre", "bob.dev", "ci-cd-bot", "carol.security", "dave.infra"]
    normal_services = ["ec2", "s3", "rds", "lambda", "cloudwatch", "iam"]
    normal_actions = [
        "DescribeInstances",
        "ListBuckets",
        "GetMetricData",
        "DescribeDBInstances",
        "GetFunction",
        "ListUsers",
        "DescribeSecurityGroups",
        "GetCallerIdentity",
    ]
    ips_usa = ["140.82.112.4", "192.168.1.45", "10.0.12.88", "198.51.100.12"]
    ips_gbr = ["51.140.88.2", "51.140.12.19"]
    ips_deu = ["35.156.40.11", "35.156.99.3"]

    for i in range(max(1, num_records - 25)):
        t = base_time + timedelta(minutes=i * 11)
        user = normal_users[i % len(normal_users)]
        action = normal_actions[i % len(normal_actions)]
        service = normal_services[i % len(normal_services)]

        if i % 3 == 0:
            ip = ips_usa[i % len(ips_usa)]
            cc = "USA"
        elif i % 3 == 1:
            ip = ips_gbr[i % len(ips_gbr)]
            cc = "GBR"
        else:
            ip = ips_deu[i % len(ips_deu)]
            cc = "DEU"

        records.append(
            {
                "timestamp": t,
                "provider": "AWS",
                "service": service,
                "event_name": action,
                "principal": user,
                "principal_type": "IAMUser" if "bot" not in user else "AssumedRole",
                "source_ip": ip,
                "country_code": cc,
                "country_name": (
                    "United States"
                    if cc == "USA"
                    else ("United Kingdom" if cc == "GBR" else "Germany")
                ),
                "status": "Success",
                "error_code": "",
                "is_error": 0,
                "is_sensitive_action": 0,
                "hour_of_day": t.hour,
                "day_of_week": t.weekday(),
            }
        )

    # 2. Injected Threat Scenario 1: Anomalous Foreign Geo-Login + Privilege Escalation
    attack_time_1 = base_time + timedelta(hours=18, minutes=15)
    records.append(
        {
            "timestamp": attack_time_1,
            "provider": "AWS",
            "service": "signin",
            "event_name": "ConsoleLogin",
            "principal": "compromised.admin",
            "principal_type": "IAMUser",
            "source_ip": "194.26.29.112",
            "country_code": "RUS",
            "country_name": "Russia",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 2,  # 2 AM off-hours
            "day_of_week": attack_time_1.weekday(),
        }
    )
    records.append(
        {
            "timestamp": attack_time_1 + timedelta(minutes=2),
            "provider": "AWS",
            "service": "iam",
            "event_name": "CreateAccessKey",
            "principal": "compromised.admin",
            "principal_type": "IAMUser",
            "source_ip": "194.26.29.112",
            "country_code": "RUS",
            "country_name": "Russia",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 2,
            "day_of_week": attack_time_1.weekday(),
        }
    )
    records.append(
        {
            "timestamp": attack_time_1 + timedelta(minutes=5),
            "provider": "AWS",
            "service": "iam",
            "event_name": "AttachUserPolicy",
            "principal": "compromised.admin",
            "principal_type": "IAMUser",
            "source_ip": "194.26.29.112",
            "country_code": "RUS",
            "country_name": "Russia",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 2,
            "day_of_week": attack_time_1.weekday(),
        }
    )
    records.append(
        {
            "timestamp": attack_time_1 + timedelta(minutes=7),
            "provider": "AWS",
            "service": "cloudtrail",
            "event_name": "StopLogging",
            "principal": "compromised.admin",
            "principal_type": "IAMUser",
            "source_ip": "194.26.29.112",
            "country_code": "RUS",
            "country_name": "Russia",
            "status": "Failure",
            "error_code": "AccessDenied",
            "is_error": 1,
            "is_sensitive_action": 1,
            "hour_of_day": 2,
            "day_of_week": attack_time_1.weekday(),
        }
    )

    # 3. Injected Threat Scenario 2: Impossible Travel & Credential Reuse
    attack_time_2 = base_time + timedelta(hours=26, minutes=30)
    records.append(
        {
            "timestamp": attack_time_2,
            "provider": "AWS",
            "service": "sts",
            "event_name": "AssumeRole",
            "principal": "alice.sre",
            "principal_type": "IAMUser",
            "source_ip": "140.82.112.4",  # Legitimate New York IP
            "country_code": "USA",
            "country_name": "United States",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 14,
            "day_of_week": attack_time_2.weekday(),
        }
    )
    # Only 8 minutes later, same identity assumed in Iran (physically impossible)
    records.append(
        {
            "timestamp": attack_time_2 + timedelta(minutes=8),
            "provider": "AWS",
            "service": "s3",
            "event_name": "PutBucketPolicy",
            "principal": "alice.sre",
            "principal_type": "IAMUser",
            "source_ip": "5.253.204.18",
            "country_code": "IRN",
            "country_name": "Iran",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 14,
            "day_of_week": attack_time_2.weekday(),
        }
    )

    # 4. Injected Threat Scenario 3: Brute-Force Password Spray
    attack_time_3 = base_time + timedelta(hours=35, minutes=10)
    for bf in range(6):
        records.append(
            {
                "timestamp": attack_time_3 + timedelta(seconds=bf * 15),
                "provider": "AWS",
                "service": "signin",
                "event_name": "ConsoleLogin",
                "principal": f"service_account_{bf}",
                "principal_type": "IAMUser",
                "source_ip": "188.130.144.20",
                "country_code": "ROU",
                "country_name": "Romania",
                "status": "Failure",
                "error_code": "FailedAuthentication",
                "is_error": 1,
                "is_sensitive_action": 0,
                "hour_of_day": 3,
                "day_of_week": attack_time_3.weekday(),
            }
        )

    # 5. Injected Threat Scenario 4: Azure Service Principal Privilege Escalation
    attack_time_4 = base_time + timedelta(hours=42)
    records.append(
        {
            "timestamp": attack_time_4,
            "provider": "Azure",
            "service": "AzureResource",
            "event_name": "roleAssignments/write",
            "principal": "sp-deployer-app",
            "principal_type": "ServicePrincipal",
            "source_ip": "175.45.176.8",
            "country_code": "PRK",
            "country_name": "North Korea",
            "status": "Success",
            "error_code": "",
            "is_error": 0,
            "is_sensitive_action": 1,
            "hour_of_day": 4,
            "day_of_week": attack_time_4.weekday(),
        }
    )

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour_of_day"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    return df.sort_values(by="timestamp").reset_index(drop=True)


def get_sample_iam_hierarchy() -> pd.DataFrame:
    """Returns multi-cloud IAM role-to-permission hierarchy for Plotly Sunburst."""
    hierarchy_data = [
        # Root Account -> Category -> Entity -> Policy -> Permission / Scope
        # 1. Cloud Administrator Roles
        {
            "Account": "Production (123456789012)",
            "Category": "Admin Roles",
            "Entity": "SuperAdminRole",
            "Policy": "AdministratorAccess",
            "Permission": "*:* (Full Cloud Control)",
            "Risk": "CRITICAL",
            "Weight": 100,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Admin Roles",
            "Entity": "SuperAdminRole",
            "Policy": "IAMFullAccess",
            "Permission": "iam:* (Manage Credentials & Roles)",
            "Risk": "CRITICAL",
            "Weight": 90,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Admin Roles",
            "Entity": "DevOpsBreakGlass",
            "Policy": "EmergencyAdminPolicy",
            "Permission": "*:* (Unrestricted Breakglass)",
            "Risk": "HIGH",
            "Weight": 85,
        },
        # 2. Workload / Compute Roles
        {
            "Account": "Production (123456789012)",
            "Category": "Compute Roles",
            "Entity": "EKSClusterWorkerRole",
            "Policy": "AmazonEKSWorkerNodePolicy",
            "Permission": "ec2:DescribeInstances, ec2:AttachVolume",
            "Risk": "LOW",
            "Weight": 40,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Compute Roles",
            "Entity": "EKSClusterWorkerRole",
            "Policy": "AmazonEKS_CNI_Policy",
            "Permission": "ec2:AssignPrivateIpAddresses",
            "Risk": "LOW",
            "Weight": 30,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Compute Roles",
            "Entity": "EC2AppInstanceRole",
            "Policy": "OverprivilegedAppPolicy",
            "Permission": "s3:*, sqs:*, iam:PassRole",
            "Risk": "HIGH",
            "Weight": 80,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Compute Roles",
            "Entity": "LambdaETLRunner",
            "Policy": "AWSLambdaBasicExecutionRole",
            "Permission": "logs:CreateLogGroup, logs:PutLogEvents",
            "Risk": "LOW",
            "Weight": 25,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Compute Roles",
            "Entity": "LambdaETLRunner",
            "Policy": "S3DataReadWritePolicy",
            "Permission": "s3:GetObject, s3:PutObject on prod-data/*",
            "Risk": "MEDIUM",
            "Weight": 50,
        },
        # 3. Developer & Service Accounts
        {
            "Account": "Production (123456789012)",
            "Category": "Developer Users",
            "Entity": "alice.developer",
            "Policy": "ReadOnlyAccess",
            "Permission": "*:Describe*, *:List*, *:Get*",
            "Risk": "LOW",
            "Weight": 35,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Developer Users",
            "Entity": "bob.developer",
            "Policy": "PowerUserAccess",
            "Permission": "*:* except iam:* and organizations:*",
            "Risk": "HIGH",
            "Weight": 75,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "Developer Users",
            "Entity": "charlie.contractor",
            "Policy": "DirectAdminPolicy (Misconfigured)",
            "Permission": "iam:CreateAccessKey, iam:AttachUserPolicy",
            "Risk": "CRITICAL",
            "Weight": 95,
        },
        # 4. CI/CD & Service Principals
        {
            "Account": "Production (123456789012)",
            "Category": "CI/CD Service Principals",
            "Entity": "github-actions-deployer",
            "Policy": "DeploymentPipelineRole",
            "Permission": "ecs:UpdateService, ecr:GetAuthorizationToken",
            "Risk": "MEDIUM",
            "Weight": 60,
        },
        {
            "Account": "Production (123456789012)",
            "Category": "CI/CD Service Principals",
            "Entity": "terraform-automation-sp",
            "Policy": "CloudResourceManagerEditor",
            "Permission": "resourcemanager.*, compute.*",
            "Risk": "HIGH",
            "Weight": 85,
        },
    ]
    return pd.DataFrame(hierarchy_data)
