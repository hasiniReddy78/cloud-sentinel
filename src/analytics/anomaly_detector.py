"""Machine Learning Anomaly Detection using scikit-learn IsolationForest."""

from dataclasses import dataclass
from typing import Dict, List, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from src.config import (
    DEFAULT_CONTAMINATION,
    HIGH_RISK_COUNTRIES,
    HOME_COUNTRIES,
    THREAT_LEVEL_THRESHOLDS,
)


@dataclass
class AnomalyResult:
    """Summary metrics of the anomaly detection analysis."""

    total_events: int
    anomalies_detected: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    anomaly_rate: float
    top_threat_actors: List[Dict[str, Any]]
    analyzed_df: pd.DataFrame


class AnomalyDetector:
    """Behavioral anomaly detector for cloud audit API telemetry using IsolationForest."""

    def __init__(self, contamination: float = DEFAULT_CONTAMINATION, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )

    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extracts and normalizes behavioral feature vectors for IsolationForest."""
        total_rows = max(len(df), 1)

        # 1. Temporal cyclical features
        hours = df["hour_of_day"].fillna(12).astype(float)
        sin_hour = np.sin(2 * np.pi * hours / 24.0)
        cos_hour = np.cos(2 * np.pi * hours / 24.0)
        day_of_week = df["day_of_week"].fillna(0).astype(float) / 6.0

        # 2. Operational risk flags
        sensitive_flag = df["is_sensitive_action"].fillna(0).astype(float)
        error_flag = df["is_error"].fillna(0).astype(float)

        # 3. Frequency / Rarity features (rare principal or action gets higher score)
        principal_counts = df["principal"].map(df["principal"].value_counts())
        principal_rarity = 1.0 - (principal_counts / total_rows)

        event_counts = df["event_name"].map(df["event_name"].value_counts())
        event_rarity = 1.0 - (event_counts / total_rows)

        # 4. Geolocation risk weight
        country_risk = df["country_code"].apply(
            lambda cc: (
                1.0 if cc in HIGH_RISK_COUNTRIES else (0.5 if cc not in HOME_COUNTRIES else 0.0)
            )
        )

        features = np.column_stack(
            [
                sin_hour,
                cos_hour,
                day_of_week,
                sensitive_flag * 2.0,
                error_flag * 1.5,
                principal_rarity,
                event_rarity,
                country_risk * 2.5,
            ]
        )
        return features

    def detect_impossible_travel(self, df: pd.DataFrame) -> List[int]:
        """Flags events where the same identity jumps between different countries in under 3 hours."""
        impossible_indices = set()
        grouped = df.sort_values(by="timestamp").groupby("principal")
        for _, group in grouped:
            if len(group) < 2:
                continue
            prev_row = None
            for idx, row in group.iterrows():
                if prev_row is not None:
                    delta_hours = (
                        row["timestamp"] - prev_row["timestamp"]
                    ).total_seconds() / 3600.0
                    if delta_hours < 3.0 and row["country_code"] != prev_row["country_code"]:
                        impossible_indices.add(idx)
                        impossible_indices.add(prev_row.name)
                prev_row = row
        return list(impossible_indices)

    def analyze(self, telemetry_df: pd.DataFrame) -> AnomalyResult:
        """Runs IsolationForest and behavioral heuristic rules on telemetry DataFrame."""
        if telemetry_df.empty:
            empty_df = telemetry_df.copy()
            empty_df["is_anomaly"] = pd.Series(dtype=bool)
            empty_df["anomaly_score"] = pd.Series(dtype=float)
            empty_df["threat_level"] = pd.Series(dtype=str)
            empty_df["anomaly_reasons"] = pd.Series(dtype=object)
            return AnomalyResult(0, 0, 0, 0, 0, 0, 0.0, [], empty_df)

        df = telemetry_df.copy().reset_index(drop=True)
        features = self._extract_features(df)

        # Fit IsolationForest
        self.model.fit(features)
        raw_predictions = self.model.predict(features)  # -1 for anomaly, 1 for normal
        decision_scores = self.model.decision_function(features)  # lower is more abnormal

        # Normalize score to 0.0 (benign) -> 1.0 (highest threat)
        min_score = decision_scores.min()
        max_score = decision_scores.max()
        if max_score > min_score:
            normalized_scores = 1.0 - ((decision_scores - min_score) / (max_score - min_score))
        else:
            normalized_scores = np.zeros_like(decision_scores)

        # Check impossible travel
        impossible_travel_indices = set(self.detect_impossible_travel(df))

        is_anomaly_list = []
        anomaly_scores = []
        threat_levels = []
        reasons_list = []

        for idx, row in df.iterrows():
            score = float(normalized_scores[idx])
            reasons = []

            # Behavioral boosts
            if idx in impossible_travel_indices:
                score = min(1.0, score + 0.35)
                reasons.append("Impossible travel velocity (< 3 hrs cross-border login)")

            if row.get("country_code") in HIGH_RISK_COUNTRIES:
                score = min(1.0, score + 0.30)
                reasons.append(f"Origin in high-threat watchlist geo: {row.get('country_name')}")

            if row.get("is_sensitive_action", 0) == 1:
                score = min(1.0, score + 0.20)
                reasons.append(f"Privilege escalation / IAM modification: {row.get('event_name')}")

            if row.get("is_error", 0) == 1:
                score = min(1.0, score + 0.15)
                reasons.append(f"API rejection/Authentication error ({row.get('error_code')})")

            # Determine anomaly status based on threshold or model flag
            is_anomaly = bool(raw_predictions[idx] == -1 or score >= 0.60 or len(reasons) >= 2)

            # Assign threat level tier
            if score >= THREAT_LEVEL_THRESHOLDS["CRITICAL"] or (
                is_anomaly and row.get("is_sensitive_action") == 1
            ):
                threat_tier = "CRITICAL"
            elif score >= THREAT_LEVEL_THRESHOLDS["HIGH"] or is_anomaly:
                threat_tier = "HIGH"
            elif score >= THREAT_LEVEL_THRESHOLDS["MEDIUM"]:
                threat_tier = "MEDIUM"
            else:
                threat_tier = "LOW"

            if not reasons and is_anomaly:
                reasons.append("Unusual statistical divergence in API access pattern")

            is_anomaly_list.append(is_anomaly)
            anomaly_scores.append(round(score, 3))
            threat_levels.append(threat_tier)
            reasons_list.append("; ".join(reasons) if reasons else "Nominal behavior")

        df["is_anomaly"] = is_anomaly_list
        df["anomaly_score"] = anomaly_scores
        df["threat_level"] = threat_levels
        df["anomaly_reasons"] = reasons_list

        # Summary statistics
        total = len(df)
        anomalies = int(df["is_anomaly"].sum())
        crit_count = int((df["threat_level"] == "CRITICAL").sum())
        high_count = int((df["threat_level"] == "HIGH").sum())
        med_count = int((df["threat_level"] == "MEDIUM").sum())
        low_count = int((df["threat_level"] == "LOW").sum())
        anomaly_rate = round((anomalies / total) * 100, 2) if total > 0 else 0.0

        # Top threat actors
        anom_df = df[df["is_anomaly"]]
        top_actors = []
        if not anom_df.empty:
            actor_summary = (
                anom_df.groupby("principal")
                .agg(
                    anomaly_count=("is_anomaly", "count"),
                    max_score=("anomaly_score", "max"),
                    threat_level=(
                        "threat_level",
                        lambda x: "CRITICAL" if "CRITICAL" in x.values else "HIGH",
                    ),
                    last_country=("country_name", "last"),
                )
                .sort_values(by="anomaly_count", ascending=False)
                .head(5)
                .reset_index()
            )
            top_actors = actor_summary.to_dict(orient="records")

        return AnomalyResult(
            total_events=total,
            anomalies_detected=anomalies,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            anomaly_rate=anomaly_rate,
            top_threat_actors=top_actors,
            analyzed_df=df,
        )
