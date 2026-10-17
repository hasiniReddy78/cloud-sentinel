"""Unit tests for IsolationForest ML anomaly detection."""

import pandas as pd
from datetime import datetime, timedelta
from src.analytics.anomaly_detector import AnomalyDetector
from src.telemetry.sample_data import get_sample_telemetry


def test_anomaly_detector_training_and_prediction():
    df = get_sample_telemetry(num_records=120)
    detector = AnomalyDetector(contamination=0.08, random_state=42)
    result = detector.analyze(df)

    assert result.total_events == len(df)
    assert result.anomalies_detected > 0
    assert result.anomaly_rate > 0.0

    analyzed = result.analyzed_df
    assert "is_anomaly" in analyzed.columns
    assert "anomaly_score" in analyzed.columns
    assert "threat_level" in analyzed.columns
    assert "anomaly_reasons" in analyzed.columns

    # Verify scores are bounded [0.0, 1.0]
    assert analyzed["anomaly_score"].min() >= 0.0
    assert analyzed["anomaly_score"].max() <= 1.0


def test_impossible_travel_detection():
    base_time = datetime(2026, 10, 16, 10, 0, 0)
    events = [
        {
            "timestamp": base_time,
            "principal": "victim.user",
            "country_code": "USA",
            "country_name": "United States",
            "source_ip": "140.82.112.4",
            "event_name": "DescribeInstances",
            "is_sensitive_action": 0,
            "is_error": 0,
            "hour_of_day": 10,
            "day_of_week": 4,
        },
        {
            # 10 minutes later in Russia -> impossible travel
            "timestamp": base_time + timedelta(minutes=10),
            "principal": "victim.user",
            "country_code": "RUS",
            "country_name": "Russia",
            "source_ip": "194.26.29.112",
            "event_name": "CreateAccessKey",
            "is_sensitive_action": 1,
            "is_error": 0,
            "hour_of_day": 10,
            "day_of_week": 4,
        },
    ]
    df = pd.DataFrame(events)
    detector = AnomalyDetector()
    impossible_indices = detector.detect_impossible_travel(df)
    assert len(impossible_indices) == 2


def test_empty_dataframe_handling():
    detector = AnomalyDetector()
    empty_df = pd.DataFrame()
    result = detector.analyze(empty_df)
    assert result.total_events == 0
    assert result.anomalies_detected == 0


def test_filtered_dataframe_non_consecutive_index():
    df = get_sample_telemetry(num_records=100)
    # Simulate filtering by selecting non-consecutive row indices
    filtered_df = df.iloc[[2, 7, 13, 21, 35, 42]].copy()
    detector = AnomalyDetector()
    result = detector.analyze(filtered_df)
    assert result.total_events == 6
    assert len(result.analyzed_df) == 6
