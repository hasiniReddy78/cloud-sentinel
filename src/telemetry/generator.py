"""Dynamic synthetic telemetry and attack scenario generator."""

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
import pandas as pd
from src.config import GEO_COORDINATES, HIGH_RISK_IAM_ACTIONS


class TelemetrySimulator:
    """Simulates multi-cloud API traffic with customizable attack injections."""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.users = ["alice.sre", "bob.dev", "ci-bot", "security-audit", "dave.ops", "emily.data"]
        self.services = ["ec2", "s3", "iam", "rds", "lambda", "sts", "cloudtrail"]
        self.standard_actions = [
            "DescribeInstances",
            "ListBuckets",
            "GetCallerIdentity",
            "DescribeLogStreams",
            "GetMetricStatistics",
            "DescribeDBInstances",
            "ListRoles",
            "GetFunctionConfiguration",
        ]
        self.attack_actions = list(HIGH_RISK_IAM_ACTIONS)
        self.home_countries = ["USA", "GBR", "DEU"]
        self.foreign_countries = ["RUS", "PRK", "IRN", "ROU", "NGA", "CHN"]

    def generate(self, total_events: int = 300, anomaly_rate: float = 0.08) -> pd.DataFrame:
        """Generates synthetic audit trail events with realistic distribution."""
        events: List[Dict[str, Any]] = []
        base_time = datetime.now(timezone.utc) - timedelta(days=3)
        num_anomalies = max(1, int(total_events * anomaly_rate))
        num_normal = total_events - num_anomalies

        # 1. Normal Events
        for i in range(num_normal):
            dt = base_time + timedelta(minutes=i * 12 + random.randint(1, 8))
            user = random.choice(self.users)
            action = random.choice(self.standard_actions)
            service = random.choice(self.services)
            country = random.choice(self.home_countries)
            geo = GEO_COORDINATES[country]

            events.append(
                {
                    "timestamp": dt,
                    "provider": "AWS",
                    "service": service,
                    "event_name": action,
                    "principal": user,
                    "principal_type": "AssumedRole" if "bot" in user else "IAMUser",
                    "source_ip": f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}",
                    "country_code": country,
                    "country_name": geo["name"],
                    "status": "Success",
                    "error_code": "",
                    "is_error": 0,
                    "is_sensitive_action": 0,
                    "hour_of_day": dt.hour,
                    "day_of_week": dt.weekday(),
                }
            )

        # 2. Injected Anomalous Events
        for j in range(num_anomalies):
            dt = base_time + timedelta(minutes=random.randint(100, total_events * 10))
            is_escalation = random.random() < 0.6
            action = random.choice(self.attack_actions) if is_escalation else "ConsoleLogin"
            user = random.choice(["attacker_lateral", "service_compromised", "stealth_user"])
            country = random.choice(self.foreign_countries)
            geo = GEO_COORDINATES[country]
            has_error = random.random() < 0.4

            events.append(
                {
                    "timestamp": dt,
                    "provider": random.choice(["AWS", "Azure"]),
                    "service": "iam" if is_escalation else "signin",
                    "event_name": action,
                    "principal": user,
                    "principal_type": "IAMUser",
                    "source_ip": f"185.220.{random.randint(100, 250)}.{random.randint(1, 254)}",
                    "country_code": country,
                    "country_name": geo["name"],
                    "status": "Failure" if has_error else "Success",
                    "error_code": "AccessDenied" if has_error else "",
                    "is_error": 1 if has_error else 0,
                    "is_sensitive_action": 1 if is_escalation else 0,
                    "hour_of_day": dt.hour,
                    "day_of_week": dt.weekday(),
                }
            )

        df = pd.DataFrame(events)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values(by="timestamp").reset_index(drop=True)
        df["hour_of_day"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        return df
